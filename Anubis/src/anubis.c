//
//  anubis.c
//  Anubis
//
//  Created by TUTU on 2016/3/30.
//  Copyright © 2016年 TUTU. All rights reserved.
//
//
//        _____   _   _   _____   _   _
//       |_   _| | | | | |_   _| | | | |
//         | |   | | | |   | |   | | | |
//         | |   | |_| |   | |   | |_| |
//         |_|    \___/    |_|    \___/
//
//
//                       _
//       /\             | |             (_)
//      /  \     _ __   | |__    _   _   _   ___
//     / /\ \   | '_ \  | '_ \  | | | | | | / __|
//    / ____ \  | | | | | |_) | | |_| | | | \__ \
//   /_/    \_\ |_| |_| |_.__/   \__,_| |_| |___/
//
//
//         ／ﾌﾌ 　　　　　　 　ム｀ヽ
//        / ノ)　　 ∧∧　　　　　）　ヽ
//     　ﾞ/ ｜　　(´・ω・`）ノ⌒（ゝ._,ノ     人類，
//       /　ﾉ⌒7⌒ヽーく　 ＼　／               你渴望力量嗎？
//       丶＿ ノ ｡　　 ノ､　　｡|/
//            `ヽ `ー-'_人`ーﾉ
//              丶 ￣ _人'彡ﾉ
//               ﾉ　　r'十ヽ/


#include "anubis.h"

static void usage(const char *cmd);
static void version(void);

int verbose;
int timestamp;
int asynchronous;
FILE *in_stream;
FILE *out_stream;
FILE *err_stream;

static struct option long_options[] = {
    {"filename", required_argument, NULL, 'f'},
    {"verbose", no_argument, NULL, 'v'},
    {"version", no_argument, NULL, 's'},
    {"fragment", required_argument, NULL, 'F'},
    {"MTU", required_argument, NULL, 'M'},
    {"ip-header-length", required_argument, NULL, 'l'},
    {"disable-timestamp", no_argument, NULL, 't'},
    {"output-filename", required_argument, NULL, 'o'},
    {"error-filename", required_argument, NULL, 'e'},
    {"list-devices", optional_argument, NULL, 'i'},
    {"asynchronous", no_argument, NULL, 'a'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}};

static void anubis_SIGINT_signal_handler(int sig) {
    anubis_err("signal(): %s\n", strsignal(sig));
    anubis_err("Anubis: bye~\n");
    
    //unregister and raise the signal again
    signal(SIGINT, SIG_DFL);
    raise(SIGINT);
    
    //exit(0);
}//end anubis_SIGINT_signal_handler

static void anubis_check_root_privilege(void) {
    int is_root = 0;
#ifndef __CYGWIN__
    is_root = ((getuid() == 0) && (getegid() == 0)) ? 1 : 0;
#else
	struct passwd *pw;
	uid_t uid;
	uid = geteuid();
	pw = getpwuid(uid);
	if (pw) {
		if (!strcmp(pw->pw_name, "Administrator"))
			is_root = 1;
	}
	else {
		anubis_perror("getpwuid()");
	}
#endif
    if(!is_root) {
        anubis_err("Ah ah ah! You didn't say the magic word!\n");
        exit(1);
    }
}//end anubis_check_root_privilege

int main(int argc, const char * argv[]) {
    
    //register
    signal(SIGINT, anubis_SIGINT_signal_handler);
    
    int c;
    int fragment_mode = 0;
    int injection_mode = 0;
    int devices_mode = 0;
    int help_mode = 0;
    int version_mode = 0;
    int option_index = 0;
    
    //defaults
    int mtu = 0;
    int data_len = 0;
    int ip_hl = 20;
    char *filename = NULL;
    char *device = NULL;
    
    in_stream = stdin;
    out_stream = stdout;
    err_stream = stderr;
    verbose = 0;
    timestamp = 1;
    asynchronous = 0;
    
    opterr = 0;
    while((c = getopt_long(argc, (char *const *)argv, "af:vF:M:hl:to:e:i::", long_options, &option_index)) != EOF) {
        switch (c) {
                //injection mode
            case 'f':
                filename = optarg;
                injection_mode = 1;
                break;
                
                case 'a':
                asynchronous = 1;
                injection_mode = 1;
                break;
                
                //fragment mode
            case 'F':
                data_len = atoi(optarg);
                if(data_len == 0) {
                    anubis_err("Anubis: \"%d\" is not a valid length\n", data_len);
                    exit(1);
                }//end if
                fragment_mode = 1;
                break;
                
            case 'M':
                mtu = atoi(optarg);
                if(mtu == 0) {
                    anubis_err("Anubis: \"%d\" is not a valid MTU\n", mtu);
                    exit(1);
                }//end if
                fragment_mode = 1;
                break;
                
            case 'l':
                ip_hl = atoi(optarg);
                if(ip_hl == 0) {
                    anubis_err("Anubis: \"%d\" is not a valid IP header length\n", ip_hl);
                    exit(1);
                }//end if
                fragment_mode = 1;
                break;
                
                //output
            case 'o':
                out_stream = fopen(optarg, "a+");
                if(!out_stream) {
                    out_stream = stdout;
                    anubis_perror("fopen()");
                }//end if
                break;
                
            case 'e':
                err_stream = fopen(optarg, "a+");
                if(!err_stream) {
                    err_stream = stderr;
                    anubis_perror("fopen()");
                }//end if
                break;
                
            case 'v': //verbose
                verbose = 1;
                break;
                
            case 't': //disable-timestamp
                timestamp = 0;
                break;
                
                //list devices
            case 'i':
                devices_mode = 1;
                if(   !optarg
                   && NULL != argv[optind]
                   && '-' != argv[optind][0] ) {
                    // This is what makes it work; if `optarg` isn't set
                    // and argv[optindex] doesn't look like another option,
                    // then assume it's our parameter and overtly modify optindex
                    // to compensate.
                    //
                    // I'm not terribly fond of how this is done in the getopt
                    // API, but if you look at the man page it documents the
                    // existence of `optarg`, `optindex`, etc, and they're
                    // not marked const -- implying they expect and intend you
                    // to modify them if needed.
                    device = (char *)argv[optind++];
                }
                break;
                
                //others
            case 's': //version
                version_mode = 1;
                break;
                
            case 'h': //help
            case '?':
            default:
                help_mode = 1;
                break;
        }
    }//end while
    
    if(argc <= 1) {
        usage(argv[0]);
    }//end if
    
    //help mode is the first priority
    if(help_mode) {
        usage(argv[0]);
    }//end if help
    
    if(version_mode) {
        version();
    }//end if
    
    //only one mode
    if((injection_mode + fragment_mode + devices_mode) > 1) {
	    anubis_err("{--filename}, {--fragment --MTU --ip-header-length} or {--list-devices} should not be appear at the same time\n");
        usage(argv[0]);
    }//end if
    
    if(fragment_mode) {
        if(data_len == 0) {
            anubis_err("Please specify -F --fragment\n");
            exit(1);
        }//end if
        
        if(mtu == 0) {
            anubis_err("Please specify -M --MTU\n");
            exit(1);
        }//end if
        
        if(ip_hl == 0) {
            anubis_err("Please specify -l --ip-header-length\n");
            exit(1);
        }//end if
        
        //calculate fragement offset
        anubis_fragment_offset(data_len, mtu, ip_hl);
        exit(0);
    }//end if
    else if(injection_mode) {
        //parse packet
        if(!filename) {
            anubis_err("Please specify -f --filename\n");
	        exit(1);
        }//end if
        else {
#ifndef __CYGWIN__
            anubis_check_root_privilege();
#endif
            anubis_parser(filename);
        }//end else
        
        exit(0);
    }//end if
    else if(devices_mode) {
#ifndef __CYGWIN__
        anubis_check_root_privilege();
#endif
        anubis_list_devices(device);
        exit(0);
    }//end if devices
    
    //unregister
    //signal(SIGINT, SIG_DFL);
    usage(argv[0]);
    return 0;
}

static void version(void) {
    anubis_err("Anubis version %s\n", ANUBIS_VERSION);
    exit(0);
}//end version

static void usage(const char *cmd) {
    anubis_err("Anubis version %s\n", ANUBIS_VERSION);
    
    anubis_err("Usage: %s [options]\n", cmd);
    
    fprintf(err_stream, "Packet injection:\n");
    fprintf(err_stream, "\t{ <-f --filename JSON configuration filename> [-a --asynchronous Asynchronous process socket] }\n");
    
    fprintf(err_stream, "IP fragment offset:\n");
    fprintf(err_stream, "\t{ <-F --fragment Data length> <-M --MTU MTU size> [-l --ip-header-length IP header length] }\n");
    
    fprintf(err_stream, "List devices:\n");
    fprintf(err_stream, "\t{ <-i --list-devices [device] List devices information> }\n");
    
    fprintf(err_stream, "Output:\n");
    fprintf(err_stream, "\t[-v --verbose Verbose] [-t --disable-timestamp Disable output timestamp]\n"
            "\t[-o --output-filename Redirect stdout to file] [-e --error-filename Redirect stderr to file]\n");
    
    fprintf(err_stream, "Other:\n");
    fprintf(err_stream, "\t{ <--version Version> }, { <-h --help Show this help> }\n");
    
    fprintf(err_stream, "\n{} is a group options, <> is required, [] is optional\n");
    anubis_err("Report bugs to <jr89197@hotmail.com>\n");
    anubis_err("Github: https://github.com/QbsuranAlang/Anubis\n");
    exit(1);
}//end usage
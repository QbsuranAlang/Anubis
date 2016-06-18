//
//  anubis_value_converter.c
//  Anubis
//
//  Created by 聲華 陳 on 2016/3/31.
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


#include "anubis.h"

struct {
    u_int32_t code;
    const char *const phrase;
} message_status[] = {
    {100, "Continue"}, {101, "Switching Protocols"}, {102, "Processing"},
    {200, "OK"}, {201, "Created"}, {202, "Accepted"},
    {203, "Non-Authoritative Information"}, {204, "No Content"}, {205, "Reset Content"},
    {206, "Partial Content"}, {207, "Multi-Status"}, {208, "Already Reported"},
    {226, "IM Used"}, {300, "Multiple Choices"}, {301, "Moved Permanently"},
    {302, "Found"}, {303, "See Other"}, {304, "Not Modified"},
    {305, "Use Proxy"}, {306, "Switch Proxy"}, {307, "Temporary Redirect"},
    {308, "Permanent Redirect"}, {400, "Bad Request"}, {401, "Unauthorized"},
    {402, "Payment Required"}, {403, "Forbidden"}, {404, "Not Found"},
    {405, "Method Not Allowed"}, {406, "Not Acceptable"}, {407, "Proxy Authentication Required"},
    {408, "Request Timeout"}, {409, "Conflict"}, {410, "Gone"},
    {411, "Length Required"}, {412, "Precondition Failed"}, {413, "Payload Too Large"},
    {414, "URI Too Long"}, {415, "Unsupported Media Type"}, {416, "Range Not Satisfiable"},
    {417, "Expectation Failed"}, {418, "I\'m a teapot"}, {421, "Misdirected Request"},
    {422, "Unprocessable Entity"}, {423, "Locked"}, {424, "Failed Dependency"},
    {426, "Upgrade Required"}, {428, "Precondition Required"}, {429, "Too Many Requests"},
    {431, "Request Header Fields Too Large"}, {451, "Unavailable For Legal Reasons"}, {500, "Internal Server Error"},
    {501, "Not Implemented"}, {502, "Bad Gateway"}, {503, "Service Unavailable"},
    {504, "Gateway Timeout"}, {505, "HTTP Version Not Supported"}, {506, "Variant Also Negotiates"},
    {507, "Insufficient Storage"}, {508, "Loop Detected"}, {510, "Not Extended"},
    {511, "Network Authentication Required"},
    //Unofficial codes
    {103, "Checkpoint"}, {420, "Method Failure"}, {420, "Enhance Your Calm"},
    {450, "Blocked by Windows Parental Controls"}, {498, "Invalid Token"}, {499, "Token Required"},
    {499, "Request has been forbidden by antivirus"}, {509, "Bandwidth Limit Exceeded"}, {530, "Site is frozen"},
    {440, "Login Timeout"}, {449, "Retry With"}, {451, "Redirect"},
    {444, "No Response"}, {495, "SSL Certificate Error"}, {496, "SSL Certificate Required"},
    {497, "HTTP Request Sent to HTTPS Port"}, {499, "Client Closed Request"}, {520, "Unknown Error"},
    {521, "Web Server Is Down"}, {522, "Connection Timed Out"}, {523, "Origin Is Unreachable"},
    {524, "A Timeout Occurred"}, {525, "SSL Handshake Failed"}, {526, "Invalid SSL Certificate"},
    {0, "Undefined"}
};

u_int8_t *anubis_mac_aton(const char *mac_address) {
    static u_int8_t buffer[ANUBIS_BUFFER_SIZE][ETHER_ADDR_LEN];
    static int which = -1;
    u_int8_t *temp = NULL;
    int len;
    which = (which + 1 == ANUBIS_BUFFER_SIZE ? 0 : which + 1);

    memset(buffer[which], 0, sizeof(buffer[which]));
    
    temp = libnet_hex_aton(mac_address, &len);
    if(!temp) {
        anubis_err("libnet_hex_aton(): invalid mac address: \"%s\"\n", mac_address);
        return NULL;
    }//end if
    
    //length is not 6
    if(len != ETHER_ADDR_LEN) {
        anubis_err("libnet_hex_aton(): invalid mac address: \"%s\"\n", mac_address);
#ifndef __CYGWIN__
	    free(temp);
#endif
        return NULL;
    }//end if
    
    memmove(buffer[which], temp, sizeof(buffer[which]));
#ifndef __CYGWIN__
    free(temp);
#endif
    
    return buffer[which];
}//end mac_aton

const char *anubis_mac_ntoa(u_int8_t *d) {
    static char buffer[ANUBIS_BUFFER_SIZE][MAC_ADDRSTRLEN];
    static int which = -1;
    which = (which + 1 == ANUBIS_BUFFER_SIZE ? 0 : which + 1);
    
    memset(buffer[which], 0, sizeof(buffer[which]));
    snprintf(buffer[which], sizeof(buffer[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
    
    return buffer[which];
}//end anubis_mac_ntoa

char *anubis_ip_ttoa(u_int8_t flag) {
    static int f[] = {'1', '1', '1', 'D', 'T', 'R', 'C', 'X'};
#define TOS_MAX (sizeof(f)/sizeof(f[0]))
    static char str[TOS_MAX + 1]; //return buffer
    u_int8_t mask = 1 << 7; //mask
    int i;
    
    for(i = 0 ; i < TOS_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;
    
    return str;
}//end anubis_ip_ttoa

char *anubis_ip_ftoa(u_int16_t flag) {
    static int f[] = {'R', 'D', 'M'}; //flag
#define IP_FLG_MAX (sizeof(f)/sizeof(f[0]))
    static char str[IP_FLG_MAX + 1]; //return buffer
    u_int16_t mask = 1 << 15; //mask
    int i;
    
    for(i = 0 ; i < IP_FLG_MAX ; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = 0;
    
    return str;
}//end anubis_ip_ftoa

char *anubis_tcp_ftoa(u_int8_t flag) {
    static int  f[] = {'W', 'E', 'U', 'A', 'P', 'R', 'S', 'F'};
#define TCP_FLG_MAX (sizeof f / sizeof f[0])
    static char str[TCP_FLG_MAX + 1];
    u_int32_t mask = 1 << 7;
    int i;
    
    for (i = 0; i < TCP_FLG_MAX; i++) {
        if(mask & flag)
            str[i] = f[i];
        else
            str[i] = '-';
        mask >>= 1;
    }//end for
    str[i] = '\0';
    
    return str;
}//end anubis_tcp_ftoa

unsigned long long anubis_string_to_int(const char *s) {
    char *tmp = (char *)strdup(s);
    unsigned long long result = 0;
    
    if(!tmp) {
        anubis_perror("strdup()");
        return 0;
    }//end if
    
    char *token = strtok(tmp, " |");
    while(token) {
        unsigned long long value = 0;
        
        if(strlen(tmp) < 2)
            value = atoll(token);
        else if(!strncasecmp(token, "0x", 2))
            sscanf(token, "%llx", &value);
        else
            sscanf(token, "%lld", &value);
        
        if(value == 0 && strncasecmp(token, "0", 1)) {
            anubis_err("anubis_string_to_int(): \"%s\" unknown token\n", token);
        }//end if
        
        result |= value;
        token = strtok(NULL, " |");
    }//end while
    
    //free
    free(tmp);
    return result;
}//end anubis_string_to_int

unsigned long long anubis_binary_to_int(const char *s, int length) {
    char *tmp = (char *)strdup(s);
    unsigned long long result = 0;
    
    if(!tmp) {
        anubis_perror("strdup()");
        return 0;
    }//end if
    
    for(int i = 0 ; i < length ; i++) {
        char bin = tmp[i];
        if (bin == '1')
            result = result * 2 + 1;
        else if (bin == '0')
            result *= 2;
    }//end for
    
    //free
    free(tmp);
    return result;
}//end anubis_binary_to_int

in_addr_t anubis_ip_aton(const char *ip_address) {
    in_addr_t ip_integer;
    int ret = inet_pton(AF_INET, ip_address, &ip_integer);
    if(ret == 0) {
        anubis_err("inet_pton(): invalid ip address: \"%s\"\n", ip_address);
        return 0;
    }//end if
    else if(ret == -1) {
        anubis_perror("inet_pton()");
        return 0;
    }//end else
    
    return ip_integer;
}//end anubis_ip_aton

const char *anubis_ip_ntoa(in_addr_t i) {
    static char buffer[ANUBIS_BUFFER_SIZE][INET_ADDRSTRLEN];
    static int which = -1;
    which = (which + 1 == ANUBIS_BUFFER_SIZE ? 0 : which + 1);
    
    memset(buffer[which], 0, sizeof(buffer[which]));
    inet_ntop(AF_INET, &i, buffer[which], sizeof(buffer[which]));
    
    return buffer[which];
}//end anubis_ip_ntoa

in_addr_t anubis_hostname_to_ip_address(const char *hostname) {
    
    struct addrinfo hints, *res;
    int status;
    in_addr_t addr = -1;
    
    anubis_verbose("Query hostname: \"%s\"\n", hostname);
    
    //hostname to ip address
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; //ipv4 only
    
    if((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        anubis_err("getaddrinfo(): %s\n", gai_strerror(status));
        return 0;
    }//end if
    else {
        for(struct addrinfo *p = res ; p ; p = p->ai_next) {
            if(p->ai_family == AF_INET) {
                addr = ((struct sockaddr_in *)p->ai_addr)->sin_addr.s_addr;
                break;
            }//end if
        }//end for
        freeaddrinfo(res);
    }//end else
    
    if(addr == -1)
        anubis_err("anubis_hostname_to_ip_address(): IP addresses are not available\n");
    
    anubis_verbose("Response IP address: \"%s\"\n", anubis_ip_ntoa(addr));
    
    return addr;
}//end anubis_hostname_to_ip_address

const char *anubis_message_status_code_to_phrase(u_int32_t code) {
    for(int i = 0 ; i < sizeof(message_status)/sizeof(message_status[0]) ; i++) {
        if(message_status[i].code == code) {
            anubis_verbose("Code: \"%d\", select phrase: \"%s\"\n", code, message_status[i].phrase);
            return message_status[i].phrase;
        }//end if
    }//end for
    
    anubis_err("anubis_message_status_code_to_phrase(): \"%d\" unknown status code\n", code);
    return message_status[sizeof(message_status)/sizeof(message_status)].phrase; //last one
}//end anubis_message_status_code_to_phrase

u_int32_t anubis_message_phrase_to_status_code(const char *phrase) {
    for(int i = 0 ; i < sizeof(message_status)/sizeof(message_status[0]) ; i++) {
        if(!strcasecmp(phrase, message_status[i].phrase)) {
            anubis_verbose("Phrase: \"%s\", select code: \"%d\"\n", phrase, message_status[i].code);
            return message_status[i].code;
        }
    }//end for
    
    anubis_err("anubis_message_status_code_to_phrase(): \"%s\" unknown phrase\n", phrase);
    return message_status[sizeof(message_status)/sizeof(message_status)].code; //last one
}//end anubis_message_phrase_to_status_code

const SSL_METHOD *anubis_string_to_SSL_METOHD(const char *method, int role) {
    if(!method)
        return NULL;
    
    if(!strcasecmp(method, "SSLv23"))
        return role == ANUBIS_ROLE_SERVER ?
        SSLv23_server_method() :
        role == ANUBIS_ROLE_CLIENT ? SSLv23_client_method() : NULL;
#ifndef OPENSSL_NO_SSL2_METHOD
    if(!strcasecmp(method, "SSLv2"))
        return role == ANUBIS_ROLE_SERVER ?
        SSLv3_server_method() :
        role == ANUBIS_ROLE_CLIENT ? SSLv3_client_method() : NULL;
#endif
#ifndef OPENSSL_NO_SSL3_METHOD
    if(!strcasecmp(method, "SSLv3"))
        return role == ANUBIS_ROLE_SERVER ?
        SSLv3_server_method() :
        role == ANUBIS_ROLE_CLIENT ? SSLv3_client_method() : NULL;
#endif
    if(!strcasecmp(method, "TLSv1.0"))
        return role == ANUBIS_ROLE_SERVER ?
        TLSv1_server_method() :
        role == ANUBIS_ROLE_CLIENT ? TLSv1_client_method() : NULL;
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
    if(!strcasecmp(method, "TLSv1.1"))
        return role == ANUBIS_ROLE_SERVER ?
        TLSv1_1_server_method() :
        role == ANUBIS_ROLE_CLIENT ? TLSv1_1_client_method() : NULL;
    if(!strcasecmp(method, "TLSv1.2"))
        return role == ANUBIS_ROLE_SERVER ?
        TLSv1_2_server_method() :
        role == ANUBIS_ROLE_CLIENT ? TLSv1_2_client_method() : NULL;
#endif
    
    /*
    if(!strcasecmp(method, "DTLS1.0"))
        return role == ANUBIS_ROLE_SERVER ?
        DTLSv1_server_method() :
        role == ANUBIS_ROLE_CLIENT ? DTLSv1_client_method() : NULL;
    if(!strcasecmp(method, "DTLS1.2"))
        return role == ANUBIS_ROLE_SERVER ?
        DTLSv1_2_server_method() :
        role == ANUBIS_ROLE_CLIENT ? DTLSv1_2_client_method() : NULL;
    if(!strcasecmp(method, "DTLS"))
        return role == ANUBIS_ROLE_SERVER ?
        DTLS_server_method() :
        role == ANUBIS_ROLE_CLIENT ? DTLS_client_method() : NULL;
     */
    
    return NULL;
}//end anubis_string_to_SSL_METOHD

#pragma mark parse function

static char *anubis_parse_param(char *prefix, char *expression) {
    
    anubis_verbose("Calling \"%s\"\n", expression);
    
    //get param
    expression += strlen(prefix) + 1;
    *(expression + strlen(expression) - 1) = 0;
    
    static char buffer[ANUBIS_BUFFER_SIZE][ANUBIS_BUFFER_SIZE] = {0};
    static int which = -1;
    which = (which + 1 == ANUBIS_BUFFER_SIZE ? 0 : which + 1);
    memset(buffer[which], 0, sizeof(buffer[which]));
    
    char *tmp = (char *)strdup(expression);
    if(!tmp) {
        anubis_perror("strdup()");
        return NULL;
    }//end if
    
    if(strlen(tmp) > ANUBIS_BUFFER_SIZE - 1) {
        anubis_err("%s(): \"%s\" should be less %d\n", prefix, tmp, ANUBIS_BUFFER_SIZE);
        free(tmp);
        return NULL;
    }//end if
    
    sscanf(tmp, " %s ", buffer[which]);
    free(tmp);
    
    return buffer[which];
}//end anubis_parse_param

u_int32_t anubis_random(char *expression) {
#define RANDOM_RANGE(low, high) \
((u_int32_t)(random() % ((high)-(low)+(1)))+(low))
    
    anubis_srand();
    //get param
    char *buffer = anubis_parse_param("random", expression);
    if(!buffer)
        return 0;
    
    if(strchr(buffer, '-')) {
        u_int32_t low = 0;
        u_int32_t high = 0;
        
        if(sscanf(buffer, " %d - %d ", &low, &high) != 2) {
            anubis_err("random(): random range format is \"integer - interger\"\n");
            return 0;
        }//end if
        
        if(low > high) {
            u_int32_t tmp = low;
            low = high;
            high = tmp;
        }//end if
        
        return RANDOM_RANGE(low, high);
    }//end if range
    else {
        
        if(!strcasecmp(buffer, "Official") || !strcasecmp(buffer, "Well-known")) {
            return RANDOM_RANGE(0, 1023);
        }//end if
        else if(!strcasecmp(buffer, "Unofficial") || !strcasecmp(buffer, "Registered")) {
            return RANDOM_RANGE(1024, 49151);
        }//end if
        else if(!strcasecmp(buffer, "Multiple use") ||
                !strcasecmp(buffer, "Dynamic") ||
                !strcasecmp(buffer, "Private") ||
                !strcasecmp(buffer, "Ephemeral")) {
            return RANDOM_RANGE(49152, 65535);
        }//end if
        else if(!strcasecmp(buffer, "u_int8_t")) {
            return RANDOM_RANGE(0, UINT8_MAX);
        }//end if
        else if(!strcasecmp(buffer, "u_int16_t")) {
            return RANDOM_RANGE(0, UINT16_MAX);
        }//end if
        else if(!strcasecmp(buffer, "u_int32_t") || strlen(buffer) == 0) { //default
            return RANDOM_RANGE(0, (u_int64_t)UINT32_MAX);
        }//end if
        else {
            anubis_err("random(): \"%s\" unknown parameter\n", buffer);
            return 0;
        }//end if
    }//end if
}//end anubis_random

in_addr_t anubis_random_ip_address(char *expression) {
    //get param
    
    anubis_srand();
    
    char *buffer = anubis_parse_param("random_ip_address", expression);
    if(!buffer)
        return 0;
    in_addr_t addr;
    
    if(strlen(buffer) == 0) {
        do {
            addr = (in_addr_t)random();
        }//end do
        while(addr == INADDR_ANY || addr == INADDR_BROADCAST ||
              IN_MULTICAST(addr) || IN_PRIVATE(addr) ||
              IN_EXPERIMENTAL(addr) || IN_LOOPBACK(addr) ||
              IN_ZERONET(addr) || IN_LOCAL_GROUP(addr));
        return addr;
    }//end if
    else {
        anubis_err("random_ip_address(): \"%s\" unknown parameter\n", buffer);
        return 0;
    }//end if
}//end anubis_random_ip_address

u_int8_t *anubis_random_mac_address(char *expression) {
    //get param
    
    anubis_srand();
    
    char *buffer = anubis_parse_param("random_mac_address", expression);
    if(!buffer)
        return NULL;
    
    if(strlen(buffer) == 0) {
        char mac_address[MAC_ADDRSTRLEN] = {0};
        
        //first byte should be an even integer
        snprintf(mac_address, sizeof(mac_address), "%02x:%02x:%02x:%02x:%02x:%02x",
                 (int)((random()%256) & ~0x01), (int)(random()%256), (int)(random()%256),
                 (int)(random()%256), (int)(random()%256), (int)(random()%256));
        return anubis_mac_aton(mac_address);
    }//end if
    else {
        anubis_err("random_mac_address(): \"%s\" unknown parameter\n", buffer);
        return NULL;
    }//end if
}//end anubis_random_mac_address

u_int8_t *anubis_lookup_mac_address(char *expression, const char *device) {
    //get param
    char *buffer = anubis_parse_param("random_mac_address", expression);
    if(!buffer)
        return NULL;
    
    if(!strcasecmp(buffer, "255.255.255.255") || !strcasecmp(buffer, "Broadcast")) {
        return (u_int8_t *)"\xff\xff\xff\xff\xff\xff";
    }//end if
    else if(!strncasecmp(buffer, "224.", 4) || !strncasecmp(buffer, "239.", 4)) {
        char mac_address[MAC_ADDRSTRLEN] = {0};
        int byte1 = 1, byte2 = 0, byte3 = 0, byte4 = 0;
        
        if(sscanf(buffer, "%d.%d.%d.%d", &byte1, &byte2, &byte3, &byte4) != 4) {
            anubis_err("lookup_mac_address(): \"%s\" is not found\n", buffer);
            return NULL;
        }//end if
        
        snprintf(mac_address, sizeof(mac_address), "01:00:5e:%02x:%02x:%02x", byte2, byte3, byte4);
        return anubis_mac_aton(mac_address);
    }//end if multicast
    else {
        arp_t *handle = arp_open();
        struct arp_entry arp_entry = {0};
        int arping = 0;
        if(!handle) {
            anubis_perror("arp_open()");
            return NULL;
        }//end if
        addr_pton(buffer, &arp_entry.arp_pa);
        
    AGAIN:
        if(arp_get(handle, &arp_entry) == 0) {
            char *mac_address = addr_ntoa(&arp_entry.arp_ha);
            arp_close(handle);
            return anubis_mac_aton(mac_address);
        }//end if
        else {
            if(arping) {
                anubis_err("lookup_mac_address(): \"%s\" is not found\n", buffer);
                arp_close(handle);
                return (u_int8_t *)"\x00\x00\x00\x00\x00\x00";
            }//end if
            else {
                //try to arping
                anubis_verbose("MAC address of \"%s\" is not found in the ARP cache, trying to arping \"%s\"\n", buffer, buffer);
                pid_t pid = fork();
                if(pid == 0) {
                    FILE *fp = NULL;
                    char tmp_filename[ANUBIS_BUFFER_SIZE] = {0};
                    char commands[ANUBIS_BUFFER_SIZE * 2] = {0};
                    char current_path[ANUBIS_BUFFER_SIZE] = {0};
                    //get current
                    memset(current_path, 0, sizeof(current_path));
                    getcwd(current_path, sizeof(current_path));
                    
                    snprintf(tmp_filename, sizeof(tmp_filename), "%s/anubis_tmpfile%ld", current_path, time(NULL));
                    
                    //temp file exsit and delete it
                    struct stat filestatus = {0};
                    if (stat(tmp_filename, &filestatus) == 0) {
						remove(tmp_filename);
                    }//end if
                    
                    fp = fopen(tmp_filename, "wt+");
                    if(!fp) {
                        anubis_perror("fopen()");
                        exit(1); //bye fork
                    }//end if
                    
                    fprintf(fp, "[{\"Socket-type\": \"Data-link\",\"Option\": {\"Device\": \"%s\"},\"Sequence\": [{\"Send Packet\": [{\"Ethernet\": {\"Destination MAC Address\": \"Broadcast\",\"Source MAC Address\": \"Myself\",\"Type\": \"ARP\"}},{\"ARP\": {\"Operation\": \"Request\",\"Sender Hardware Address\": \"myself\",\"Sender Protocol Address\": \"myself\",\"Target Hardware Address\": \"00:00:00:00:00:00\",\"Target Protocol Address\": \"%s\"}}]}]}]", device, buffer);
                    fflush(fp);
                    fclose(fp);
                    
                    snprintf(commands, sizeof(commands), "%s/anubis -f %s > /dev/null 2>&1", current_path, tmp_filename);
                    
                    //try three time
                    anubis_verbose("Arping \"%s\" for three times\n", buffer);
                    for(int i = 0 ; i < 3 ; i++)
                        system(commands);
                    
					remove(tmp_filename);
                    anubis_wait_microsecond(800000); //wait 800 ms
                }//end if
                else if(pid < 0) {
                    anubis_perror("fork()");
                }//end if
                
#ifdef __CYGWIN__
	            wait(0);
#else
	            wait(NULL);
#endif //wait fork finish
	            
                arping = 1;
                goto AGAIN;
            }
        }//end else
    }//end else
}//end anubis_lookup_mac_address

//libdnet callback
static int arp_lookup_ip_address(const struct arp_entry *arp_entry, void *arg) {
    struct arp_entry *addr = (struct arp_entry *)arg;
    
    if(!addr_cmp(&addr->arp_ha, &arp_entry->arp_ha)) {
        memmove(&addr->arp_pa, &arp_entry->arp_pa, sizeof(addr->arp_pa));
        return 1;
    }//end if found
    return 0;
}

in_addr_t anubis_lookup_ip_address(char *expression) {
    //get param
    char *buffer = anubis_parse_param("random_ip_address", expression);
    if(!buffer)
        return 0;
    
    if(!strcasecmp(buffer, "ff:ff:ff:ff:ff:ff") || !strcasecmp(buffer, "Broadcast")) {
        return INADDR_BROADCAST;
    }//end if
    else {
        arp_t *handle = arp_open();
        struct arp_entry arp_entry = {0};
        if(!handle) {
            anubis_perror("arp_open()");
            return 0;
        }//end if
        
        addr_pton(buffer, &arp_entry.arp_ha);
        int ret = arp_loop(handle, arp_lookup_ip_address, (void *)&arp_entry);
        if(ret == 1) {
            char *ip_address = addr_ntoa(&arp_entry.arp_pa);
            arp_close(handle);
            return anubis_ip_aton(ip_address);
        }//end if
        else {
            anubis_err("lookup_ip_address(): \"%s\" is not found\n", buffer);
            arp_close(handle);
            return 0;
        }//end else
    }//end else
}//end anubis_lookup_ip_address

in_addr_t anubis_multicast_address(char *expression) {
    
    char *buffer = anubis_parse_param("multicast_address", expression);
    if(!buffer)
        return 0;
    
#define MULTICAST_ADDRESS(x, y) \
    if(!strcasecmp(buffer, x)) \
        return anubis_ip_aton(y);
    
    MULTICAST_ADDRESS("RIPv2", "224.0.0.9");
    MULTICAST_ADDRESS("SSDP", "239.255.255.250");
    
#undef MULTICAST_ADDRESS
    anubis_err("multicast_address(): \"%s\" unknown parameter\n", buffer);
    return 0;
}//end anubis_multicast_address

u_int16_t anubis_port(char *expression) {
    char *buffer = anubis_parse_param("port", expression);
    if(!buffer)
        return 0;
    
#define PORT(x, y) \
if(!strcasecmp(buffer, x)) \
return y;
    
    PORT("HTTP", 80);
    PORT("HTTPS", 443);
    PORT("DNS", 53);
    PORT("SSH", 22);
    PORT("Telnet", 23);
    PORT("RIP", 520);
    PORT("Wake-On-LAN", 9);
    PORT("WOL", 9);
    PORT("SSDP", 1900);
    PORT("DHCP-client", 68);
    PORT("DHCP-server", 67);
    
#undef PORT
    anubis_err("port(): \"%s\" unknown parameter\n", buffer);
    return 0;
}//end anubis_port
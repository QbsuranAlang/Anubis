//
//  anubis.h
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


#ifndef anubis_h
#define anubis_h

#define __FAVOR_BSD
#include <unistd.h>
#include <sys/time.h>
#include <sys/param.h>
#include <math.h>
#include <ifaddrs.h>
    //#define PACK( __Declaration__ ) __Declaration__ __attribute__((__packed__))
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <getopt.h>

#ifndef __linux
    /*BSD*/
#ifndef __CYGWIN__
#include <net/bpf.h>
#include <net/if_dl.h>
#include <sys/sysctl.h>
#endif
#include <net/if.h>
#include <netinet/in.h>
#include <pwd.h>
#else
    /*Linux*/
#define AF_LINK AF_PACKET
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/if_link.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif
    //#define PACK( __Declaration__ ) __pragma( pack(push, 1) ) __Declaration__ __pragma( pack(pop) )

#include "json.h"
#include <dnet.h>
#include <pcap.h>
#include <libnet.h>
//#ifdef WIN32
//#define _WINSOCKAPI_
//#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdarg.h>

#define ANUBIS_VERSION "1.1.2"

#ifndef MAC_ADDRSTRLEN
#define MAC_ADDRSTRLEN 2*6+5+1
#endif
#define ANUBIS_BUFFER_SIZE 256

#ifndef IN_PRIVATE
#define	IN_PRIVATE(i)	((((u_int32_t)(i) & 0xff000000) == 0x0a000000) || \
(((u_int32_t)(i) & 0xfff00000) == 0xac100000) || \
(((u_int32_t)(i) & 0xffff0000) == 0xc0a80000))
#endif
#ifndef IN_LOOPBACK
#define IN_LOOPBACK(i)		(((u_int32_t)(i) & 0xff000000) == 0x7f000000)
#endif
#ifndef IN_ZERONET
#define IN_ZERONET(i)		(((u_int32_t)(i) & 0xff000000) == 0)
#endif
#ifndef IN_LOCAL_GROUP
#define	IN_LOCAL_GROUP(i)	(((u_int32_t)(i) & 0xffffff00) == 0xe0000000)
#endif
#ifndef INADDR_LOOPBACK
#define	INADDR_LOOPBACK		(u_int32_t)0x7f000001
#endif

#ifndef UINT8_MAX
#define UINT8_MAX         255
#endif
#ifndef UINT16_MAX
#define UINT16_MAX        65535
#endif
#ifndef UINT32_MAX
#define UINT32_MAX        4294967295U
#endif
#ifndef UINT64_MAX
#define UINT64_MAX        18446744073709551615ULL
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#include "anubis_structure.h"
#include "anubis_stream.h"
#include "anubis_parser.h"
#include "anubis_defaults.h"
#include "anubis_value_converter.h"
#include "anubis_writer.h"
#include "anubis_time.h"
#include "anubis_dumper.h"
#include "anubis_libnet_extension.h"
#include "anubis_value_checker.h"
#include "anubis_extra.h"
#include "anubis_model.h"

#if !defined(HAVE_STRLCAT) && !defined(strlcat)
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#if !defined(HAVE_STRLCPY) && !defined(strlcpy)
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif
#if !defined(HAVE_STRDUP)
char *strdup(const char *str);
#endif

#if !defined(HAVE_SNPRINTF) && !defined(snprintf)
extern int snprintf(char *, size_t, const char *, /*args*/ ...);
#endif

/*global variable*/
extern int verbose;
extern int timestamp;
extern int asynchronous;
extern FILE *in_stream;
extern FILE *out_stream;
extern FILE *err_stream;

#ifdef __CYGWIN__
int _errno;
#endif

#endif /* anubis_h */

//
//  anubis_win32.h
//  Anubis
//
//  Created by 聲華 陳 on 2016/4/21.
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


#ifndef anubis_win32_h
#define anubis_win32_h

#ifdef WIN32

#ifndef STATIC_GETOPT
#define STATIC_GETOPT
#endif
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif

#define NOCRYPT 
#include <winsock2.h> 
#include <iphlpapi.h>
#include <direct.h>
#include <limits.h>
#include <Lmcons.h>
#include <sys/types.h>
#include <stdbool.h>
#include "getopt.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "libnet.lib")
#pragma comment(lib, "dnet.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")


#define WSA_VERSION MAKEWORD(2, 2) // using winsock 2.2
typedef unsigned int u_int32_t;
typedef u_int32_t in_addr_t;
typedef u_int32_t pid_t;
#define strlcpy(x, y, z) strcpy_s(x, z, y)
#define strlcat(x, y, z) strcat_s(x, z, y)
#define lrint(f)  ((long)(f))
#define strcasecmp _stricmp
#define strncasecmp  _strnicmp
#define getcwd _getcwd
#define IPVERSION 4
#define	TCPOPT_EOL		0
#define	TCPOPT_NOP		1
#define	TCPOPT_MAXSEG		2
#define TCPOPT_SACK_PERMITTED	4		/* Experimental */
#define TCPOPT_WINDOW		3

int gettimeofday(struct timeval *tp, struct timezone *tzp);
pid_t fork(void);
pid_t wait(int *stat_loc);
#endif

#endif /* anubis_win32_h */

//
//  anubis_stream.h
//  Anubis
//
//  Created by 聲華 陳 on 2016/3/30.
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


#ifndef anubis_err_h
#define anubis_err_h

void anubis_perror(char *s);
void anubis_ssl_perror(char *s);
void anubis_in(char *out_buffer, int out_length);
void anubis_in_stream(FILE *in_fp, char *out_buffer, int out_length);
#ifndef WIN32
void anubis_err(const char *fmt, ...) __attribute__((format (__printf__, 1, 2)));
void anubis_out(const char *fmt, ...) __attribute__((format (__printf__, 1, 2)));
void anubis_verbose(const char *fmt, ...) __attribute__((format (__printf__, 1, 2)));
#else
void anubis_err(const char *fmt, ...) __attribute__((format (printf, 1, 2)));
void anubis_out(const char *fmt, ...) __attribute__((format (printf, 1, 2)));
void anubis_verbose(const char *fmt, ...) __attribute__((format (printf, 1, 2)));
#endif

#endif /* anubis_err_h */

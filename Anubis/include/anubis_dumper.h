//
//  anubis_dumper.h
//  Anubis
//
//  Created by TUTU on 2016/4/2.
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


#ifndef anubis_dumper_h
#define anubis_dumper_h

void anubis_dump_ethernet(u_int32_t *dump_length, u_int32_t total_length, const u_int8_t *content);
void anubis_dump_libnet_content(libnet_t *handle, int transport_layer, int is_application_layer);
void anubis_dump_application(const char *content, u_int32_t length);
void anubis_dump_server_certificate(SSL *ssl);

#endif /* anubis_dumper_h */

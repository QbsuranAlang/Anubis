//
//  anubis_model_arpoison.h
//  Anubis
//
//  Created by TUTU on 2016/6/26.
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


#ifndef anubis_model_arpoison_h
#define anubis_model_arpoison_h

void anubis_default_model_arpoison(anubis_model_t *model);
void anubis_parse_model_arpoison(json_value *json, anubis_model_t *model);

typedef struct {
    anubis_model_t model;
    in_addr_t *host_list;
    int host_list_length;
    in_addr_t reversed_ip_address;
    u_int32_t interval;
    in_addr_t *white_list;
    int white_list_length;
    char *arp_sha;
    uint16_t ar_pro;
    in_addr_t current_ip_address;
    u_int64_t index;
    u_int64_t round;
    int swap;
} anubis_model_arpoison_t;

#endif /* anubis_model_arpoison_h */

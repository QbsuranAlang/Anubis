//
//  anubis_model_arping.h
//  Anubis
//
//  Created by TUTU on 2016/6/25.
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


#ifndef anubis_model_arping_h
#define anubis_model_arping_h

void anubis_default_model_arping(anubis_model_t *model);
void anubis_parse_model_arping(json_value *json, anubis_model_t *model);
void anubis_arping(const char *device, const char *ip_address);

typedef struct {
    anubis_model_t model;
    u_int32_t arp_target;
} anubis_model_arping_t;

#endif /* anubis_model_arping_h */
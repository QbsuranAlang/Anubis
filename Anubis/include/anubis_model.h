//
//  anubis_model.h
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


#ifndef anubis_model_h
#define anubis_model_h

#include "anubis_model_arping.h"
#include "anubis_model_arpoison.h"

pcap_t *anubis_open_pcap(char *device, int to_ms, char *filter);
void anubis_save_to_file(const char *filename, const char *json);

#endif /* anubis_model_h */

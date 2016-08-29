//
//  anubis_parse_wol.c
//  Anubis
//
//  Created by TUTU on 2016/6/23.
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

void anubis_parse_wol_hdr(json_value *json, anubis_wol_hdr *wol_hdr, const char *device) {
    
    CHECK_OBJECT_TYPE(json, "Wake-On-LAN", "Wake-On-LAN");
    
    int required_mac = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Sync Stream")) {
            anubis_parse_mac_address("Wake-On-LAN", name, value,
                                     wol_hdr->sync_stream, sizeof(wol_hdr->sync_stream),
                                     device, NULL);
        }//end if
        else if(!strcasecmp(name, "MAC Address")) {
            u_int8_t mac[6] = {0};
            anubis_parse_mac_address("MAC Address", name, value,
                                     mac, sizeof(mac), device, &required_mac);
            
            if(!required_mac)
                continue;
            
            for(int i = 0; i < sizeof(wol_hdr->mac_address)/sizeof(wol_hdr->mac_address[0]) ; i++) {
                memmove(wol_hdr->mac_address[i], mac, sizeof(wol_hdr->mac_address[i]));
            }//end for
        }//end if
        else if(!strcasecmp(name, "Password")) {
            anubis_parse_mac_address("Wake-On-LAN", name, value,
                                     wol_hdr->password, sizeof(wol_hdr->password),
                                     device, NULL);
        }//end if
        else {
            anubis_err("Wake-On-LAN: \"%s\" unknown field\n", name);
        }//end else
        
    }//end for
    
    CHECK_REQUIREMENT(required_mac, "Wake-On-LAN", "MAC Address");
}//end anubis_parse_wol_hdr
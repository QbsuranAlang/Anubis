//
//  anubis_parse_udp.c
//  Anubis
//
//  Created by TUTU on 2016/6/23.
//
//
//        _____   _   _   _____   _   _
//       |_   _| | | | | |_   _| | | | |
//         | |   | | | |   | |   | | | |
//         | |   | |_| |   | |   | |_| |
//         |_|    \___/    |_|    \___/
//
//
//                               _       _
//       /\                     | |     (_)
//      /  \     _ __    _   _  | |__    _   ___
//     / /\ \   | '_ \  | | | | | '_ \  | | / __|
//    / ____ \  | | | | | |_| | | |_) | | | \__ \
//   /_/    \_\ |_| |_|  \__,_| |_.__/  |_| |___/


#include "anubis.h"

void anubis_parse_udp_hdr(json_value *json, struct libnet_udp_hdr *udp_hdr) {
    
    CHECK_OBJECT_TYPE(json, "UDP", "UDP");
    
    int src_port = 0;
    int dst_port = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Source Port")) {
            if(value->type == json_string && IS_RANDOM(value->u.string.ptr)) {
                udp_hdr->uh_sport = (u_int16_t)anubis_random(value->u.string.ptr);
                src_port = 1;
            }//end if
            else if(value->type == json_string && IS_PORT(value->u.string.ptr)) {
                udp_hdr->uh_sport = anubis_port(value->u.string.ptr);
                if(udp_hdr->uh_sport != 0)
                    src_port = 1;
            }//end if
            else
                anubis_parse_2bytes_integer("UDP", name, value, &udp_hdr->uh_sport, &src_port);
        }//end if
        else if(!strcasecmp(name, "Destination Port")) {
            if(value->type == json_string && IS_RANDOM(value->u.string.ptr)) {
                udp_hdr->uh_dport = (u_int16_t)anubis_random(value->u.string.ptr);
                dst_port = 1;
            }//end if
            else if(value->type == json_string && IS_PORT(value->u.string.ptr)) {
                udp_hdr->uh_dport = (u_int16_t)anubis_port(value->u.string.ptr);
                if(udp_hdr->uh_dport != 0)
                    dst_port = 1;
            }//end if
            else
                anubis_parse_2bytes_integer("UDP", name, value, &udp_hdr->uh_dport, &dst_port);
        }//end if
        else if(!strcasecmp(name, "Length")) {
            if(value->type == json_string && !strcasecmp(value->u.string.ptr, "auto")) {
                udp_hdr->uh_ulen = 0;
                continue;
            }//end if
            else
                anubis_parse_2bytes_integer("UDP", name, value, &udp_hdr->uh_ulen, NULL);
        }//end if
        else if(!strcasecmp(name, "Checksum")) {
            if(value->type == json_string && !strcasecmp(value->u.string.ptr, "auto")) {
                udp_hdr->uh_sum = 0;
                continue;
            }//end if
            anubis_parse_2bytes_integer("UDP", name, value, &udp_hdr->uh_sum, NULL);
        }//end if
        else {
            anubis_err("UDP: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    CHECK_REQUIREMENT(src_port, "UDP", "Source Port");
    CHECK_REQUIREMENT(dst_port, "UDP", "Destination Port");
    
}//end anubis_parse_udp_hdr

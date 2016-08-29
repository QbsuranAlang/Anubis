//
//  anubis_parse_arp.c
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

void anubis_parse_arp_hdr(json_value *json, anubis_ether_arp_t *arp_hdr, const char *device) {
    
    CHECK_OBJECT_TYPE(json, "ARP", "ARP");
    
    int op = 0;
    int sha = 0;
    int spa = 0;
    int tha = 0;
    int tpa = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Hardware Type")) {
            anubis_parse_2bytes_integer("ARP", name, value,
                                        &arp_hdr->arp_hrd, NULL);
        }//end if
        else if(!strcasecmp(name, "Protocol Type")) {
            anubis_parse_2bytes_integer("ARP", name, value,
                                        &arp_hdr->arp_pro, NULL);
        }//end if
        else if(!strcasecmp(name, "Hardware Address Length")) {
            anubis_parse_byte_integer("ARP", name, value,
                                      &arp_hdr->arp_hln , NULL);
        }//end if
        else if(!strcasecmp(name, "Protocol Address Length")) {
            anubis_parse_byte_integer("ARP", name, value,
                                      &arp_hdr->arp_pln, NULL);
        }//end if
        else if(!strcasecmp(name, "Operation")) {
            CHECK_INTEGER_OR_STRING_TYPE(value, "ARP");
            
            if(value->type == json_integer) {
                anubis_parse_2bytes_integer("ARP", name, value, &arp_hdr->arp_op, &op);
                continue;
            }//end if
            
            COMPARE_DEFINE(value->u.string.ptr, ARPOP_REPLY, arp_hdr->arp_op, op)
            else
                COMPARE_DEFINE(value->u.string.ptr, ARPOP_REQUEST, arp_hdr->arp_op, op)
            else
                COMPARE_DEFINE(value->u.string.ptr, ARPOP_REVREPLY, arp_hdr->arp_op, op)
            else
                COMPARE_DEFINE(value->u.string.ptr, ARPOP_REVREQUEST, arp_hdr->arp_op, op)
            else
                anubis_parse_2bytes_integer("ARP", name, value, &arp_hdr->arp_op, &op);
            
        }//end if
        else if(!strcasecmp(name, "Sender Hardware Address")) {
            anubis_parse_mac_address("ARP", name, value,
                                     arp_hdr->arp_sha, sizeof(arp_hdr->arp_sha),
                                     device, &sha);
        }//end if
        else if(!strcasecmp(name, "Sender Protocol Address")) {
            anubis_parse_ip_address("ARP", name, value,
                                    (in_addr_t *)arp_hdr->arp_spa, sizeof(arp_hdr->arp_spa),
                                    device, &spa);
        }//end if
        else if(!strcasecmp(name, "Target Hardware Address")) {
            anubis_parse_mac_address("ARP", name, value,
                                     arp_hdr->arp_tha, sizeof(arp_hdr->arp_tha),
                                     device, &tha);
        }//end if
        else if(!strcasecmp(name, "Target Protocol Address")) {
            anubis_parse_ip_address("ARP", name, value,
                                    (in_addr_t *)arp_hdr->arp_tpa, sizeof(arp_hdr->arp_tpa),
                                    device, &tpa);
        }//end if
        else {
            anubis_err("ARP: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    CHECK_REQUIREMENT(op, "ARP", "Operation");
    CHECK_REQUIREMENT(sha, "ARP", "Sender Hardware Address");
    CHECK_REQUIREMENT(spa, "ARP", "Sender Protocol Address");
    CHECK_REQUIREMENT(tha, "ARP", "Target Hardware Address");
    CHECK_REQUIREMENT(tpa, "ARP", "Target Protocol Address");
    
}//end anubis_parse_arp_hdr

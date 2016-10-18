//
//  anubis_parse_ethernet.c
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

void anubis_parse_ethernet_hdr(json_value *json, struct libnet_ethernet_hdr *ethernet_hdr, const char *device) {
    
    CHECK_OBJECT_TYPE(json, "Ethernet", "Ethernet");
    
    int dst_addr = 0;
    int type = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Destination MAC Address")) {
            anubis_parse_mac_address("Ethernet", name, value,
                                     ethernet_hdr->ether_dhost, sizeof(ethernet_hdr->ether_dhost),
                                     device, &dst_addr);
        }//end if
        else if(!strcasecmp(name, "Source MAC Address")) {
            anubis_parse_mac_address("Ethernet", name, value,
                                     ethernet_hdr->ether_shost, sizeof(ethernet_hdr->ether_shost),
                                     device, NULL);
        }//end if
        else if(!strcasecmp(name, "Type")) {
            CHECK_INTEGER_OR_STRING_TYPE(value, "Ethernet");
            
            if(value->type == json_integer) {
                anubis_parse_2bytes_integer("Ethernet", name, value, &ethernet_hdr->ether_type, &type);
                continue;
            }//end if
            
            COMPARE_DEFINE(value->u.string.ptr, ETHERTYPE_ARP, ethernet_hdr->ether_type, type)
            else
                COMPARE_DEFINE(value->u.string.ptr, ETHERTYPE_REVARP, ethernet_hdr->ether_type, type)
            else
                COMPARE_DEFINE(value->u.string.ptr, ETHERTYPE_IP, ethernet_hdr->ether_type, type)
            else
                COMPARE_DEFINE(value->u.string.ptr, ETHERTYPE_WOL, ethernet_hdr->ether_type, type)
            else
                anubis_parse_2bytes_integer("Ethernet", name, value, &ethernet_hdr->ether_type, &type);
            
        }//end if
        else {
            anubis_err("Ethernet: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    CHECK_REQUIREMENT(dst_addr, "Ethernet", "Destination MAC Address");
    CHECK_REQUIREMENT(type, "Ethernet", "Type");
    
}//end anubis_parse_ethernet_hdr

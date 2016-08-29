//
//  anubis_parse_icmp.c
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

void anubis_parse_icmp_hdr(json_value *json, anubis_icmp_t *icmp_hdr, const char *device) {
    
    CHECK_OBJECT_TYPE(json, "ICMPv4", "ICMPv4");
    
    int type = 0;
    int code = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Type")) {
            CHECK_INTEGER_OR_STRING_TYPE(value, "ICMPv4");
            
            if(value->type == json_integer) {
                anubis_parse_byte_integer("ICMPv4", name, value, &icmp_hdr->icmp_type, &type);
                continue;
            }//end if
            
            char *ptr = value->u.string.ptr;
            
            COMPARE_DEFINE(ptr, ICMP_ECHO, icmp_hdr->icmp_type, type)
            else
                COMPARE_DEFINE(ptr, ICMP_TIMXCEED, icmp_hdr->icmp_type, type)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH, icmp_hdr->icmp_type, type)
            else
                COMPARE_DEFINE(ptr, ICMP_REDIRECT, icmp_hdr->icmp_type, type)
            else
                anubis_parse_byte_integer("ICMPv4", name, value, &icmp_hdr->icmp_type, &type);
        }//end if
        else if(!strcasecmp(name, "code")) {
            CHECK_INTEGER_OR_STRING_TYPE(value, "ICMPv4");
            
            if(value->type == json_integer) {
                anubis_parse_byte_integer("ICMPv4", name, value, &icmp_hdr->icmp_code, &code);
                continue;
            }//end if
            
            char *ptr = value->u.string.ptr;
            
            COMPARE_DEFINE(ptr, ICMP_TIMXCEED_INTRANS, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_TIMXCEED_REASS, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_NET, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_HOST, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_PROTOCOL, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_PORT, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_NEEDFRAG, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_SRCFAIL, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_NET_UNKNOWN, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_HOST_UNKNOWN, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_ISOLATED, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_NET_PROHIB, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_HOST_PROHIB, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_TOSNET, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_TOSHOST, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_FILTER_PROHIB, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_HOST_PRECEDENCE, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_UNREACH_PRECEDENCE_CUTOFF, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_REDIRECT_NET, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_REDIRECT_HOST, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_REDIRECT_TOSNET, icmp_hdr->icmp_code, code)
            else
                COMPARE_DEFINE(ptr, ICMP_REDIRECT_TOSHOST, icmp_hdr->icmp_code, code)
            else
                anubis_parse_byte_integer("ICMPv4", name, value, &icmp_hdr->icmp_code, &code);
            
        }//end if
        else if(!strcasecmp(name, "Checksum")) {
            if(value->type == json_string && !strcasecmp(value->u.string.ptr, "auto")) {
                icmp_hdr->icmp_cksum = 0;
                continue;
            }//end if
            anubis_parse_2bytes_integer("ICMPv4", name, value, &icmp_hdr->icmp_cksum, NULL);
        }//end if
        else if(!strcasecmp(name, "Identifier")) {
            if(value->type == json_string && IS_RANDOM(value->u.string.ptr))
                icmp_hdr->icmp_id = (u_int16_t)anubis_random(value->u.string.ptr);
            else
                anubis_parse_2bytes_integer("ICMPv4", name, value, &icmp_hdr->icmp_id, NULL);
        }//end if
        else if(!strcasecmp(name, "Sequence number") || !strcasecmp(name, "seq")) {
            if(value->type == json_string && IS_RANDOM(value->u.string.ptr))
                icmp_hdr->icmp_seq = (u_int16_t)anubis_random(value->u.string.ptr);
            else
                anubis_parse_2bytes_integer("ICMPv4", name, value, &icmp_hdr->icmp_seq, NULL);
        }//end if
        else if(!strcasecmp(name, "Next MTU")) {
            anubis_parse_2bytes_integer("ICMPv4", name, value, &icmp_hdr->icmp_nextmtu, NULL);
        }//end if
        else if(!strcasecmp(name, "Gateway")) {
            anubis_parse_ip_address("ICMPv4", name, value,
                                    (in_addr_t *)&icmp_hdr->icmp_gwaddr.s_addr, sizeof(icmp_hdr->icmp_gwaddr.s_addr),
                                    device, NULL);
        }//end if
        else {
            anubis_err("ICMPv4: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    CHECK_REQUIREMENT(type, "ICMPv4", "Type");
    CHECK_REQUIREMENT(code, "ICMPv4", "Code");
    
}//end anubis_parse_icmp_hdr

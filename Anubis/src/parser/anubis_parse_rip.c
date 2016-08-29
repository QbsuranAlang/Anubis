//
//  anubis_parse_rip.c
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

void anubis_parse_rip_hdr(json_value *json, anubis_packet_raw_data_t *rip_hdr, const char *device) {
    
    CHECK_OBJECT_TYPE(json, "RIP", "RIP");
    
    int required_cmd = 0;
    int required_ver = 0;
    uint8_t rip_cmd = 0;
    uint8_t rip_ver = 0;
    u_int16_t rip_rd = 0;
    
    int current_len = 4; //RIP(Command + Version + Route Damain) is 4
    u_int8_t option_tmp[65535 - 20 - 8 - 4] = {0}; //maximux packet size - IP - UDP - RIP(Command + Version + Route Damain)
    memset(option_tmp, 0, sizeof(option_tmp));
    
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Command")) {
            CHECK_INTEGER_OR_STRING_TYPE(value, "RIP");
            
            if(value->type == json_integer) {
                anubis_parse_byte_integer("RIP", name, value, &rip_cmd, &required_cmd);
                continue;
            }//end if
            
            COMPARE_DEFINE(value->u.string.ptr, RIPCMD_REQUEST, rip_cmd, required_cmd)
            else
                COMPARE_DEFINE(value->u.string.ptr, RIPCMD_RESPONSE, rip_cmd, required_cmd)
            else
                COMPARE_DEFINE(value->u.string.ptr, RIPCMD_TRACEON, rip_cmd, required_cmd)
            else
                COMPARE_DEFINE(value->u.string.ptr, RIPCMD_TRACEOFF, rip_cmd, required_cmd)
            else
                COMPARE_DEFINE(value->u.string.ptr, RIPCMD_POLL, rip_cmd, required_cmd)
            else
                COMPARE_DEFINE(value->u.string.ptr, RIPCMD_POLLENTRY, rip_cmd, required_cmd)
            else
                anubis_parse_byte_integer("RIP", name, value, &rip_cmd, &required_cmd);
        }//end if
        else if(!strcasecmp(name, "Version")) {
            CHECK_INTEGER_OR_STRING_TYPE(value, "RIP");
            
            if(value->type == json_integer) {
                anubis_parse_byte_integer("RIP", name, value, &rip_ver, &required_ver);
                continue;
            }//end if
            
            COMPARE_DEFINE(value->u.string.ptr, RIPVER_0, rip_ver, required_ver)
            else
                COMPARE_DEFINE(value->u.string.ptr, RIPVER_1, rip_ver, required_ver)
            else
                COMPARE_DEFINE(value->u.string.ptr, RIPVER_2, rip_ver, required_ver)
            else
                anubis_parse_byte_integer("RIP", name, value, &rip_ver, &required_ver);
            
        }//end if
        else if(!strcasecmp(name, "Routing Domain")) {
            anubis_parse_2bytes_integer("RIP", name, value, &rip_rd, NULL);
        }//end if
        else if(!strcasecmp(name, "Route Table Entry") || !strcasecmp(name, "RTE")) {
            if(value->type != json_array) {
                anubis_err("RIP: \"Route Table Entry\" should be an array\n");
                continue;
            }//end if
            
            for(int j = 0 ; j < value->u.array.length ; j++) {
                json_value *rte_object = value->u.array.values[j];
                if(rte_object->type != json_object) {
                    anubis_err("RIP: \"Route Table Entry\": RTE should be an object\n");
                    continue;
                }//end if
                
                anubis_rte_t rte = {0};
                
                memset(&rte, 0, sizeof(rte));
                
                int required_family = 0;
                int required_addr = 0;
                int required_mask = 0;
                int required_metric = 0;
                
                for(int k = 0 ; k < rte_object->u.object.length ; k++) {
                    json_char *name = rte_object->u.object.values[k].name;
                    json_value *value = rte_object->u.object.values[k].value;
                    
                    if(!strcasecmp(name, "Address Family")) {
                        CHECK_INTEGER_OR_STRING_TYPE(value, "RIP: \"Route Table Entry\"");
                        
                        if(value->type == json_integer) {
                            anubis_parse_2bytes_integer("RIP: \"Route Table Entry\"", name, value, &rte.rip_af, &required_family);
                            continue;
                        }//end if
                        
                        COMPARE_DEFINE(value->u.string.ptr, AF_INET, rte.rip_af, required_family)
                        else
                            anubis_parse_2bytes_integer("RIP: \"Route Table Entry\"", name, value, &rte.rip_af, &required_family);
                        
                    }//end if
                    else if(!strcasecmp(name, "Route Tag")) {
                        anubis_parse_2bytes_integer("RIP: \"Route Table Entry\"", name, value, &rte.rip_rt, NULL);
                    }//end if
                    else if(!strcasecmp(name, "IP Address")) {
                        anubis_parse_ip_address("RIP: \"Route Table Entry\"", name, value,
                                                &rte.rip_addr, sizeof(rte.rip_addr),
                                                device, &required_addr);
                    }//end if
                    else if(!strcasecmp(name, "Netmask")) {
                        anubis_parse_ip_address("RIP: \"Route Table Entry\"", name, value,
                                                &rte.rip_mask, sizeof(rte.rip_mask),
                                                device, &required_mask);
                    }//end if
                    else if(!strcasecmp(name, "Next hop")) {
                        anubis_parse_ip_address("RIP: \"Route Table Entry\"", name, value,
                                                &rte.rip_next_hop, sizeof(rte.rip_next_hop),
                                                device, NULL);
                    }//end if
                    else if(!strcasecmp(name, "Metric")) {
                        anubis_parse_4bytes_integer("RIP: \"Route Table Entry\"", name, value, &rte.rip_metric, &required_metric);
                    }//end if
                    else {
                        anubis_err("RIP: \"Route Table Entry\": \"%s\" unknown field\n", name);
                    }//end else
                }//end for each rte
                
                CHECK_REQUIREMENT(required_family, "RIP: \"Route Table Entry\"", "Address Family");
                CHECK_REQUIREMENT(required_addr, "RIP: \"Route Table Entry\"", "IP Address");
                CHECK_REQUIREMENT(required_mask, "RIP: \"Route Table Entry\"", "Netmask");
                CHECK_REQUIREMENT(required_metric, "RIP: \"Route Table Entry\"", "Metric");
                
                rte.rip_af = htons(rte.rip_af);
                rte.rip_rt = htons(rte.rip_rt);
                rte.rip_metric = htonl(rte.rip_metric);
                
                //copy data
                memmove(option_tmp + current_len, &rte, ANUBIS_RTE_H);
                current_len += ANUBIS_RTE_H;
            }//end for rte
            
        }//end if rte
        else {
            anubis_err("RIP: \"%s\" unknown field\n", name);
        }//end else
        
    }//end for
    
    CHECK_REQUIREMENT(required_cmd, "RIP", "Command");
    CHECK_REQUIREMENT(required_ver, "RIP", "Version");
    
    option_tmp[0] = rip_cmd;
    option_tmp[1] = rip_ver;
    rip_rd = htons(rip_rd);
    memmove(option_tmp + 2, &rip_rd, sizeof(rip_rd));
    
    rip_hdr->data_length = current_len < sizeof(option_tmp) ? current_len : sizeof(option_tmp);
    rip_hdr->data = (u_int8_t *)malloc(rip_hdr->data_length);
    if(!rip_hdr->data) {
        anubis_perror("malloc()");
        return;
    }//end if
    memmove(rip_hdr->data, option_tmp, rip_hdr->data_length);
}//end anubis_parse_rip_hdr

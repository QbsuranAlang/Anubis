//
//  anubis_parse_ipv4.c
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

void anubis_parse_ip_hdr(json_value *json, struct libnet_ipv4_hdr *ip_hdr, const char *device) {
    
    CHECK_OBJECT_TYPE(json, "IPv4", "IPv4");
    
    int p = 0;
    int dst_ip = 0;
    
    for(int i = 0 ; i < json->u.object.length ; i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Type of Service")) {
             anubis_parse_bit_binary("IPv4", name, value, &ip_hdr->ip_tos, 8, NULL);
         }//end if
         else if(!strcasecmp(name, "Total Length")) {
             if(value->type == json_string && !strcasecmp(value->u.string.ptr, "auto")) {
                 ip_hdr->ip_len = 0;
                 continue;
             }//end if
             else
                 anubis_parse_2bytes_integer("IPv4", name, value, &ip_hdr->ip_len, NULL);
         }//end if
         else if(!strcasecmp(name, "Identification")) {
             if(value->type == json_string && IS_RANDOM(value->u.string.ptr))
                 ip_hdr->ip_id = (u_int16_t)anubis_random(value->u.string.ptr);
             else
                 anubis_parse_2bytes_integer("IPv4", name, value, &ip_hdr->ip_id, NULL);
         }//end if
         else if(!strcasecmp(name, "Flags")) {
             if(value->type != json_string) {
                 anubis_err("IPv4: \"%s\" should be a string\n", name);
                 continue;
             }//end if
             
             char *tmp = (char *)strdup(value->u.string.ptr);
             u_int16_t result = 0;
             
             if(!tmp) {
                 anubis_perror("strdup()");
                 continue;
             }//end if
             
             char *token = strtok(tmp, " |");
             while(token) {
                 COMPARE_FLAGS(token, IP_RF, result)
                 else
                     COMPARE_FLAGS(token, IP_DF, result)
                 else
                     COMPARE_FLAGS(token, IP_MF, result)
                 else
                     anubis_err("IPv4: \"%s\" should be \"IP_RF\", \"IP_DF\" or \"IP_MF\" only\n", name);
                 
                 token = strtok(NULL, " |");
             }//end while
             
             //free
             free(tmp);
             
             ip_hdr->ip_off |= result;
         }//end if
         else if(!strcasecmp(name, "Fragment Offset")) {
             u_int16_t offset = 0;
             anubis_parse_2bytes_integer("IPv4", name, value, &offset, NULL);
             ip_hdr->ip_off |= (offset >> 3);
         }//end if
         else if(!strcasecmp(name, "Time to Live")) {
             anubis_parse_byte_integer("IPv4", name, value, &ip_hdr->ip_ttl, NULL);
         }//end if
         else if(!strcasecmp(name, "Protocol")) {
             CHECK_INTEGER_OR_STRING_TYPE(value, "IPv4");
             
             if(value->type == json_integer) {
                 anubis_parse_byte_integer("IPv4", name, value, &ip_hdr->ip_p, &p);
                 continue;
             }//end if
             
             char *ptr = value->u.string.ptr;
             
             COMPARE_DEFINE(ptr, IPPROTO_ICMP, ip_hdr->ip_p, p)
             else
                 COMPARE_DEFINE(ptr, IPPROTO_UDP, ip_hdr->ip_p, p)
             else
                 COMPARE_DEFINE(ptr, IPPROTO_TCP, ip_hdr->ip_p, p)
             else
                 anubis_parse_byte_integer("IPv4", name, value, &ip_hdr->ip_p, &p);
             
         }//end if
         else if(!strcasecmp(name, "Header Checksum")) {
             if(value->type == json_string && !strcasecmp(value->u.string.ptr, "auto")) {
                 ip_hdr->ip_sum = 0;
                 continue;
             }//end if
             anubis_parse_2bytes_integer("IPv4", name, value, &ip_hdr->ip_sum, NULL);
         }//end if
         else if(!strcasecmp(name, "Source IP Address")) {
             anubis_parse_ip_address("IPv4", name, value,
                                     (in_addr_t *)&ip_hdr->ip_src.s_addr, sizeof(ip_hdr->ip_src.s_addr),
                                     device, NULL);
         }//end if
         else if(!strcasecmp(name, "Destination IP Address")) {
             anubis_parse_ip_address("IPv4", name, value,
                                     (in_addr_t *)&ip_hdr->ip_dst.s_addr, sizeof(ip_hdr->ip_dst.s_addr),
                                     device, &dst_ip);
         }
         else {
             anubis_err("IPv4: \"%s\" unknown field\n", name);
         }//end else
    }//end for
    
    CHECK_REQUIREMENT(p, "IPv4", "Protocol");
    CHECK_REQUIREMENT(dst_ip, "IPv4", "Destination IP Address");
    
}//end anubis_parse_ip_hdr

void anubis_parse_ip_options(json_value *json, anubis_options_t *options, const char *device) {
    
    CHECK_ARRAY_TYPE(json, "IPv4 Options", "IPv4 Options");
    
    int current_len = 0;
    u_int8_t option_tmp[40] = {0};
    memset(option_tmp, 0, sizeof(option_tmp));
    
    for(int i = 0 ; i < json->u.array.length ; i++) {
        json_value *option_object = json->u.array.values[i];
        
        if(option_object->type != json_object) {
            anubis_err("%s: each option entry should be an object\n", "IPv4 Options");
            continue;
        }//end if
        
        u_int8_t type = 0;
        int required_type = 0;
        for(int j = 0 ; j < option_object->u.object.length ; j++) {
            json_char *name = option_object->u.object.values[j].name;
            json_value *value = option_object->u.object.values[j].value;
            
            if(!strcasecmp(name, "Type")) {
                
                CHECK_INTEGER_OR_STRING_TYPE(value, "IPv4 Options");
                
                if(value->type == json_integer) {
                    anubis_parse_byte_integer("IPv4 Options", name, value, &type, &required_type);
                    break;
                }//end if
                
                COMPARE_DEFINE(value->u.string.ptr, IPOPT_RR, type, required_type)
                else
                    COMPARE_DEFINE(value->u.string.ptr, IPOPT_EOL, type, required_type)
                else
                    anubis_parse_byte_integer("IPv4 Options", name, value, &type, &required_type);
                
                break;
            }//end if
        }//end for
        
        //set type failure
        CHECK_REQUIREMENT(required_type, "IPv4 Options", "Type");
        if(!required_type)
            continue;
        
        //parse each type fields
        char prefix_type[ANUBIS_BUFFER_SIZE] = {0};
        snprintf(prefix_type, sizeof(prefix_type), "IPv4 Options: Type(%d)", type);
        switch (type) {
            case IPOPT_RR: //record route
            {
                u_int8_t length = 39;
                u_int8_t pointer = 4;
                in_addr_t routes[9] = {0};
                int data_len = 0;
                int route_count = 0;
                
                //parse
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }//end if
                    else if(!strcasecmp(name, "Pointer")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &pointer, NULL);
                    }//end if
                    else if(!strncasecmp(name, "Route", 5)) {
                        char *tmp = name + strlen("Route");
                        int route_tag = atoi(tmp);
                        if(route_tag <= 0 || route_tag > 9) {
                            anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                            continue;
                        }//end if
                        
                        routes[route_tag - 1] = 0;
                        anubis_parse_ip_address(prefix_type, name, value,
                                                (in_addr_t *)&routes[route_tag - 1], sizeof(routes[route_tag - 1]),
                                                device, NULL);
                    }//end if
                    else if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//end if
                }//end for
                
                //check length
                data_len = length - 3; //substract type, length, pointer
                route_count = data_len / 4; //ip address length is 4
                
                if(data_len % 4) {
                    anubis_err("%s: \"%s\": should be divided by 4\n", prefix_type, "Length");
                }//end if
                
                if(route_count > 9) {
                    anubis_err("%s: \"%s\": out of bound\n", prefix_type, "Length");
                }//end if
                
                option_tmp[current_len++] = type;
                option_tmp[current_len++] = length;
                option_tmp[current_len++] = pointer;
                for(int i = 0 ; i < route_count ; i++) {
                    memmove(&option_tmp[current_len], &routes[i], sizeof(routes[i]));
                    current_len += sizeof(in_addr_t);
                }//end for
            }//end if record route
                
                break;
                
            case IPOPT_EOL: //EOL
                //parse
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    
                    if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//end if
                }//end for
                current_len++;
                break;
                
            default:
                anubis_err("IPv4 Options: \"%d\" unknown IP option\n", type);
                continue; //next loop
        }//end switch
        
        //reach max ip option len
        if(current_len >= sizeof(option_tmp)) {
            anubis_verbose("IPv4 Options: Reach maximum option length: %d bytes\n", (int)sizeof(option_tmp));
            break;
        }//end if
    }//end for
    
    //copy data
    if(current_len == 0)
        return;
    options->options_length = current_len < sizeof(option_tmp) ? current_len : sizeof(option_tmp);
    options->options = (u_int8_t *)malloc(options->options_length);
    if(!options->options) {
        anubis_perror("malloc()");
        return;
    }//end if
    memmove(options->options, option_tmp, options->options_length);
    
    anubis_verbose("IPv4 Options: Option length: %d bytes\n", current_len);
}//end anubis_parse_ip_options

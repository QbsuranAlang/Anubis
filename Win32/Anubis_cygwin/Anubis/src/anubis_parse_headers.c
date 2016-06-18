//
//  anubis_parse_headers.c
//  Anubis
//
//  Created by 聲華 陳 on 2016/3/31.
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

static void anubis_parse_message_hdr(char *prefix, json_value *json, anubis_message_hdr *message_hdr);

void anubis_parse_ethernet_hdr(json_value *json, struct libnet_ethernet_hdr *ethernet_hdr, const char *device) {
    
    CHECK_HEADER_TYPE(json, "Ethernet");
    
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

void anubis_parse_arp_hdr(json_value *json, anubis_ether_arp_t *arp_hdr, const char *device) {

    CHECK_HEADER_TYPE(json, "ARP");
    
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

void anubis_parse_wol_hdr(json_value *json, anubis_wol_hdr *wol_hdr, const char *device) {
    
    CHECK_HEADER_TYPE(json, "Wake-On-LAN");
    
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

void anubis_parse_ip_hdr(json_value *json, struct libnet_ipv4_hdr *ip_hdr, const char *device) {
    
    CHECK_HEADER_TYPE(json, "IPv4");
    
    int p = 0;
    int dst_ip = 0;
    
    for(int i = 0 ; i < json->u.object.length ; i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        /*if(!strcasecmp(name, "Header Length")) {
            u_int8_t ptr = (u_int8_t)ip_hdr->ip_hl;
            anubis_parse_byte_integer("IPv4", name, value, &ptr, NULL);
            ip_hdr->ip_hl = ptr;
        }//end if
        else */if(!strcasecmp(name, "Type of Service")) {
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
    
    CHECK_OPTION_TYPE(json, "IPv4 Options");
    
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

void anubis_parse_udp_hdr(json_value *json, struct libnet_udp_hdr *udp_hdr) {
    
    CHECK_HEADER_TYPE(json, "UDP");
    
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

void anubis_parse_tcp_hdr(json_value *json, struct libnet_tcp_hdr *tcp_hdr) {
    
    CHECK_HEADER_TYPE(json, "TCP");
    
    int src_port = 0;
    int dst_port = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Source Port")) {
            if(value->type == json_string && IS_RANDOM(value->u.string.ptr)) {
                tcp_hdr->th_sport = (u_int16_t)anubis_random(value->u.string.ptr);
                src_port = 1;
            }//end if
            else if(value->type == json_string && IS_PORT(value->u.string.ptr)) {
                tcp_hdr->th_sport = anubis_port(value->u.string.ptr);
                if(tcp_hdr->th_sport != 0)
                    src_port = 1;
            }//end if
            else
                anubis_parse_2bytes_integer("TCP", name, value, &tcp_hdr->th_sport, &src_port);
        }//end if
        else if(!strcasecmp(name, "Destination Port")) {
            if(value->type == json_string && IS_RANDOM(value->u.string.ptr)) {
                tcp_hdr->th_dport = (u_int16_t)anubis_random(value->u.string.ptr);
                dst_port = 1;
            }//end if
            else if(value->type == json_string && IS_PORT(value->u.string.ptr)) {
                tcp_hdr->th_dport = anubis_port(value->u.string.ptr);
                if(tcp_hdr->th_dport != 0)
                    dst_port = 1;
            }//end if
            else
                anubis_parse_2bytes_integer("TCP", name, value, &tcp_hdr->th_dport, &dst_port);
        }//end if
        else if(!strcasecmp(name, "Seq") || !strcasecmp(name, "Sequence number")) {
            anubis_parse_4bytes_integer("TCP", name, value, &tcp_hdr->th_seq, NULL);
        }//end if
        else if(!strcasecmp(name, "Ack") || !strcasecmp(name, "Acknowledgment number")) {
            anubis_parse_4bytes_integer("TCP", name, value, &tcp_hdr->th_ack, NULL);
        }//end if
        else if(!strcasecmp(name, "Header length")) {
            u_int16_t len = 0;
            anubis_parse_2bytes_integer("TCP", name, value, &len, NULL);
            tcp_hdr->th_off = len >> 2;
        }//end if
        else if(!strcasecmp(name, "Flags")) {
            if(value->type != json_string) {
                anubis_err("TCP: \"%s\" should be a string\n", name);
                continue;
            }//end if
            
            char *tmp = (char *)strdup(value->u.string.ptr);
            u_int8_t result = 0;
            
            if(!tmp) {
                anubis_perror("strdup()");
                continue;
            }//end if
            
            char *token = strtok(tmp, " |");
            while(token) {
                COMPARE_FLAGS(token, TH_FIN, result)
                else COMPARE_FLAGS(token, TH_SYN, result)
                else COMPARE_FLAGS(token, TH_RST, result)
                else COMPARE_FLAGS(token, TH_PUSH, result)
                else COMPARE_FLAGS(token, TH_ACK, result)
                else COMPARE_FLAGS(token, TH_URG, result)
                else COMPARE_FLAGS(token, TH_ECE, result)
                else COMPARE_FLAGS(token, TH_CWR, result)
                else
                    anubis_err("TCP: \"%s\" should be \"TH_FIN\", \"TH_SYN\", \"TH_RST\", \"TH_PUSH\", \"TH_ACK\", \"TH_URG\", \"TH_ECE\" or \"TH_CER\"\n", name);

                token = strtok(NULL, " |");
            }//end while
            
            //free
            free(tmp);
            
            tcp_hdr->th_flags |= result;
        }//end if
        else if(!strcasecmp(name, "Window")) {
            anubis_parse_2bytes_integer("TCP", name, value, &tcp_hdr->th_win, NULL);
        }//end if
        else if(!strcasecmp(name, "Checksum")) {
            if(value->type == json_string && !strcasecmp(value->u.string.ptr, "auto")) {
                tcp_hdr->th_sum = 0;
                continue;
            }//end if
            anubis_parse_2bytes_integer("TCP", name, value, &tcp_hdr->th_sum, NULL);
        }//end if
        else if(!strcasecmp(name, "Urgent Pointer")) {
            anubis_parse_2bytes_integer("TCP", name, value, &tcp_hdr->th_urp, NULL);
        }//end if
        else {
            anubis_err("TCP: \"%s\" unknown field\n", name);
        }//end else
        
    }//end for
    
    CHECK_REQUIREMENT(src_port, "TCP", "Source Port");
    CHECK_REQUIREMENT(dst_port, "TCP", "Destination Port");
    
}//end anubis_parse_tcp_hdr

void anubis_parse_tcp_options(json_value *json, anubis_options_t *options, const char *device) {
    
    CHECK_OPTION_TYPE(json, "TCP Options");
    
    int current_len = 0;
    u_int8_t option_tmp[40] = {0};
    memset(option_tmp, 0, sizeof(option_tmp));
    
    for(int i = 0 ; i < json->u.array.length ; i++) {
        json_value *option_object = json->u.array.values[i];
        
        if(option_object->type != json_object) {
            anubis_err("%s: each option entry should be an object\n", "TCP Options");
            continue;
        }//end if
        
        u_int8_t type = 0;
        int required_type = 0;
        for(int j = 0 ; j < option_object->u.object.length ; j++) {
            json_char *name = option_object->u.object.values[j].name;
            json_value *value = option_object->u.object.values[j].value;
            
            if(!strcasecmp(name, "Type")) {
                
                CHECK_INTEGER_OR_STRING_TYPE(value, "TCP Options");
                
                if(value->type == json_integer) {
                    anubis_parse_byte_integer("TCP Options", name, value, &type, &required_type);
                    break;
                }//end if
                
                COMPARE_DEFINE(value->u.string.ptr, TCPOPT_MAXSEG, type, required_type)
                else
                    COMPARE_DEFINE(value->u.string.ptr, TCPOPT_SACK_PERMITTED, type, required_type)
                else
                    COMPARE_DEFINE(value->u.string.ptr, TCPOPT_WINDOW, type, required_type)
                else
                    COMPARE_DEFINE(value->u.string.ptr, TCPOPT_EOL, type, required_type)
                else
                    COMPARE_DEFINE(value->u.string.ptr, TCPOPT_NOP, type, required_type)
                else
                    anubis_parse_byte_integer("TCP Options", name, value, &type, &required_type);
                
                break;
            }//end if
        }//end for
        
        //set type failure
        CHECK_REQUIREMENT(required_type, "TCP Options", "Type");
        if(!required_type)
            continue;
        
        //parse each type fields
        char prefix_type[ANUBIS_BUFFER_SIZE] = {0};
        snprintf(prefix_type, sizeof(prefix_type), "TCP Options: Type(%d)", type);
        switch (type) {
            case TCPOPT_MAXSEG: //maximum segment size
            {
                u_int8_t length = 4;
                u_int16_t mss = 0;
                int required_mss = 0;
                
                //parse
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }//end if
                    else if(!strcasecmp(name, "MSS Value")) {
                        anubis_parse_2bytes_integer(prefix_type, name, value, &mss, &required_mss);
                        mss = htons(mss);
                    }//end if
                    else if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//end if
                }//end for
                
                CHECK_OPTION_REQUIREMENT(required_mss, "TCP Options", type, "MSS Value");
                
                option_tmp[current_len++] = type;
                option_tmp[current_len++] = length;
                memmove(option_tmp + current_len, &mss, sizeof(mss));
                current_len += length - 2;
            }//end if type maximum segment size
                break;
                
            case TCPOPT_SACK_PERMITTED: //sack permitted
            {
                u_int8_t length = 2;
                //get length
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }//end if
                    else if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//end if
                }//end for
                
                option_tmp[current_len++] = type;
                option_tmp[current_len] = length;
                current_len += length - 1;
            }//end if sack permitted
                break;
                
            case TCPOPT_WINDOW:
            {
                u_int8_t length = 3;
                u_int8_t count = 0;
                int required_count = 0;
                
                //get length
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }//end if
                    else if(!strcasecmp(name, "Shift count")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &count, &required_count);
                    }
                    else if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//end if
                }//end for
                
                CHECK_OPTION_REQUIREMENT(required_count, "TCP Options", type, "Shift count");
                
                option_tmp[current_len++] = type;
                option_tmp[current_len++] = length;
                option_tmp[current_len] = count;
                current_len += length - 2;
            }//end if window
                break;
                
            case TCPOPT_EOL:
            {
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
            }//end if eol
                break;
                
            case TCPOPT_NOP:
            {
                //parse
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    
                    if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//end if
                }//end for
                option_tmp[current_len++] = type;
                
            }//end if nop
                break;
                
            default:
                anubis_err("TCP Options: \"%d\" unknown TCP option\n", type);
                continue; //next loop
        }//end switch
        
        //reach max tcp option len
        if(current_len >= sizeof(option_tmp)) {
            anubis_verbose("TCP Options: Reach maximum option length: %d bytes\n", (int)sizeof(option_tmp));
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
    
    anubis_verbose("TCP Options: Option length: %d bytes\n", current_len);
}//end anubis_parse_tcp_options

void anubis_parse_icmp_hdr(json_value *json, anubis_icmp_t *icmp_hdr, const char *device) {
    
    CHECK_HEADER_TYPE(json, "ICMP");
    
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
    
}//end anubis_parse_icmp_echo_hdr

void anubis_parse_rip_hdr(json_value *json, anubis_packet_raw_data_t *rip_hdr, const char *device) {
    
    CHECK_HEADER_TYPE(json, "RIP");
    
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

void anubis_parse_ssdp_hdr(json_value *json, anubis_message_hdr *ssdp_hdr) {
    
    anubis_parse_message_hdr("SSDP", json, ssdp_hdr);
    
}//end anubis_parse_ssdp_hdr

void anubis_parse_http_hdr(json_value *json, anubis_message_hdr *http_hdr) {
    
    anubis_parse_message_hdr("HTTP", json, http_hdr);
    
}//end anubis_parse_http_hdr

static void anubis_parse_message_hdr(char *prefix, json_value *json, anubis_message_hdr *message_hdr) {
    
    CHECK_HEADER_TYPE(json, prefix);
    int request = 0;
    int response = 0;
    int required_field = 0;
    char prefix_request[ANUBIS_BUFFER_SIZE] = {0};
    char prefix_response[ANUBIS_BUFFER_SIZE] = {0};
    char prefix_field[ANUBIS_BUFFER_SIZE] = {0};
    
    snprintf(prefix_request, sizeof(prefix_request), "%s: \"Request\"", prefix);
    snprintf(prefix_response, sizeof(prefix_response), "%s: \"Response\"", prefix);
    snprintf(prefix_field, sizeof(prefix_field), "%s: \"Field\"", prefix);
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Request")) {
            request = 1;
            if(value->type != json_object) {
                anubis_err("%s: \"Request\" should be an object\n", prefix);
                continue;
            }//end if
            
            int required_method = 0;
            int required_url = 0;
            message_hdr->type = ANUBIS_MESSAGE_REQUEST;
            
            for(int j = 0 ; j < value->u.object.length ; j++) {
                json_char *name = value->u.object.values[j].name;
                json_value *field = value->u.object.values[j].value;
                
                if(!strcasecmp(name, "Method")) {
                    anubis_parse_string(prefix_request, name, field, &message_hdr->method, &required_method);
                }
                else if(!strcasecmp(name, "URL")) {
                    anubis_parse_string(prefix_request, name, field, &message_hdr->url, &required_url);
                }
                else if(!strcasecmp(name, "Version")) {
                    anubis_parse_string(prefix_request, name, field, &message_hdr->version, NULL);
                }//end if
                else {
                    anubis_err("%s: \"%s\" unknown field\n", prefix_request, name);
                }//end else
            }//end for
            
            CHECK_REQUIREMENT(required_method, prefix_request, "Method");
            CHECK_REQUIREMENT(required_url, prefix_request, "URL");
        }//end if
        else if(!strcasecmp(name, "Response")) {
            response = 1;
            if(value->type != json_object) {
                anubis_err("%s: \"Response\" should be an object\n", prefix);
                continue;
            }//end if
            
            int required_code = 0;
            int required_phrase = 0;
            message_hdr->type = ANUBIS_MESSAGE_RESPONSE;
            
            for(int j = 0 ; j < value->u.object.length ; j++) {
                json_char *name = value->u.object.values[j].name;
                json_value *field = value->u.object.values[j].value;
                
                if(!strcasecmp(name, "Version")) {
                    anubis_parse_string(prefix_response, name, field, &message_hdr->version, NULL);
                }//end if
                else if(!strcasecmp(name, "Status Code")) {
                    anubis_parse_4bytes_integer(prefix_response, name, field, &message_hdr->status_code, &required_code);
                }//end if
                else if(!strcasecmp(name, "Phrase")) {
                    anubis_parse_string(prefix_response, name, field, &message_hdr->phrase, &required_phrase);
                }//end if
                else {
                    anubis_err("%s: \"%s\" unknown field\n", prefix_response, name);
                }//end else
                
                if(required_code && !required_phrase) {
                    message_hdr->phrase = (char *)anubis_message_status_code_to_phrase(message_hdr->status_code);
                }//end if code only
                else if(required_phrase && !required_code) {
                    message_hdr->status_code = anubis_message_phrase_to_status_code(message_hdr->phrase);
                }//end if phrase
                
            }//end for
        }//end if
        else if(!strcasecmp(name, "Field")) {
            if(value->type != json_object) {
                anubis_err("%s: \"Field\" should be an object\n", prefix);
                continue;
            }//end if
            required_field = 1;
            
            json_value *keys = NULL;
            json_value *values = NULL;
            
            for(int j = 0; j < value->u.object.length ; j++) {
                json_char *name = value->u.object.values[j].name;
                json_value *array = value->u.object.values[j].value;
                
                if(!strcasecmp(name, "Keys")) {
                    keys = array;
                }//end if
                else if(!strcasecmp(name, "Values")) {
                    values = array;
                }//end if
                else {
                    anubis_err("%s: \"%s\" unknown field\n", prefix_field, name);
                }//end else
            }//end for
            
            
            //check
            CHECK_REQUIREMENT(keys, prefix_field, "Keys");
            CHECK_REQUIREMENT(values, prefix_field, "Values");
            if(!keys || !values)
                continue;
            
            if(keys->type != json_array) {
                anubis_err("%s: \"Fields\" should be an array\n", prefix_field);
                continue;
            }//end if
            
            if(values->type != json_array) {
                anubis_err("%s: \"Values\" should be an array\n", prefix_field);
                continue;
            }//end if
            
            //parse fields
            message_hdr->keys = (char **)malloc(sizeof(char *) * keys->u.array.length);
            message_hdr->keys_lines = keys->u.array.length;
            if(!message_hdr->keys) {
                anubis_perror("malloc()");
                continue;
            }//end if
            for(int j = 0 ; j < keys->u.array.length ; j++) {
                if(keys->u.array.values[j]->type != json_string) {
                    anubis_err("%s: \"Fields\": all should be a string\n", prefix_field);
                    continue;
                }//end if
                message_hdr->keys[j] = keys->u.array.values[j]->u.string.ptr;
            }//end for
            
            //parse values
            message_hdr->values = (char **)malloc(sizeof(char *) * values->u.array.length);
            message_hdr->values_lines = values->u.array.length;
            if(!message_hdr->values) {
                anubis_perror("malloc()");
                continue;
            }//end if
            for(int j = 0 ; j < values->u.array.length ; j++) {
                if(values->u.array.values[j]->type != json_string) {
                    anubis_err("%s: \"Values\": all should be a string\n", prefix_field);
                    continue;
                }//end if
                message_hdr->values[j] = values->u.array.values[j]->u.string.ptr;
            }//end for
        }//end if message
        else {
            anubis_err("%s: \"%s\" unknown field\n", prefix, name);
        }//end else
    }//end for
    
    if(request && response)
        anubis_err("%s: \"Request\" and \"Response\" should not be appear at the same time\n", prefix);
    if(!request && !response)
        anubis_err("%s: \"Request\" or \"Response\" should be appear one of them\n", prefix);
    CHECK_REQUIREMENT(required_field, prefix, "Field");
    if(message_hdr->keys_lines != message_hdr->values_lines)
        anubis_err("%s: \"Field\": \"Keys\" and \"Values\" count should be the same\n", prefix);
    
    int status_line_length = 0;
    if(message_hdr->type == ANUBIS_MESSAGE_REQUEST) {
        if(message_hdr->method)
            status_line_length += strlen(message_hdr->method);
        if(message_hdr->url)
            status_line_length += 1 + strlen(message_hdr->url);
        if(message_hdr->version)
            status_line_length += 1 + strlen(message_hdr->version);
        status_line_length += strlen("\r\n");
        
        message_hdr->status_line = (char *)malloc(status_line_length + 1);
        if(!message_hdr->status_line) {
            anubis_perror("malloc()");
            return;
        }//end if
        
        memset(message_hdr->status_line, 0, status_line_length + 1);
        snprintf(message_hdr->status_line, status_line_length + 1, "%s %s %s\r\n",
                 message_hdr->method ? message_hdr->method : "",
                 message_hdr->url ? message_hdr->url : "",
                 message_hdr->version ? message_hdr->version : "");
        message_hdr->length += status_line_length;
    }//end if
    else if (message_hdr->type == ANUBIS_MESSAGE_RESPONSE) {
        if(message_hdr->version)
            status_line_length += strlen(message_hdr->version);
        char code[ANUBIS_BUFFER_SIZE] = {0};
        snprintf(code, sizeof(code), "%d", message_hdr->status_code);
        status_line_length += 1 + strlen(code);
        if(message_hdr->phrase)
            status_line_length += 1 + strlen(message_hdr->phrase);
        status_line_length += strlen("\r\n");
        
        message_hdr->status_line = (char *)malloc(status_line_length + 1);
        if(!message_hdr->status_line) {
            anubis_perror("malloc()");
            return;
        }//end if
        
        memset(message_hdr->status_line, 0, status_line_length + 1);
        snprintf(message_hdr->status_line, status_line_length + 1, "%s %s %s\r\n",
                 message_hdr->version ? message_hdr->version : "",
                 code,
                 message_hdr->phrase ? message_hdr->phrase : "");
        message_hdr->length += status_line_length;
    }//end if response
    
    //count messages total length
    int message_line_length = 0;
    for(int i = 0 ; i < MIN(message_hdr->keys_lines, message_hdr->values_lines) ; i++) {
        char *field = message_hdr->keys[i];
        char *value = message_hdr->values[i];
        message_line_length += (int)(strlen(field) + strlen(": ") + strlen(value) + strlen("\r\n"));
    }//end for
    
    message_line_length += (int)strlen("\r\n");
    
    message_hdr->fields = (char *)malloc(message_line_length + 1);
    if(!message_hdr->fields) {
        anubis_perror("malloc()");
        return;
    }//end if
    
    memset(message_hdr->fields, 0, message_line_length + 1);
    for(int i = 0 ; i < MIN(message_hdr->keys_lines, message_hdr->values_lines) ; i++) {
        char *field = message_hdr->keys[i];
        char *value = message_hdr->values[i];
        snprintf(message_hdr->fields, message_line_length + 1, "%s%s: %s\r\n", message_hdr->fields, field, value);
    }//end for
    strlcat(message_hdr->fields, "\r\n", message_line_length + 1);
    message_hdr->length += message_line_length;
    
    //all data
    message_hdr->data = (char *)malloc(message_hdr->length + 1);
    if(!message_hdr->data) {
        anubis_perror("malloc()");
        return;
    }//end if
    
    memset(message_hdr->data, 0, message_hdr->length + 1);
    memmove(message_hdr->data, message_hdr->status_line, status_line_length);
    memmove(message_hdr->data + status_line_length, message_hdr->fields, message_line_length);
}//end anubis_parse_message_hdr

void anubis_parse_dhcp_hdr(json_value *json, struct libnet_dhcpv4_hdr *dhcp_hdr, const char *device) {
    CHECK_HEADER_TYPE(json, "DHCPv4");
    
    int op = 0;
    
    //get address length first
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Hardware Address Length")) {
            anubis_parse_byte_integer("DHCPv4", name, value, &dhcp_hdr->dhcp_hlen, NULL);
            break;
        }//end if
    }
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Hardware Address Length")) {

        }
        else if(!strcasecmp(name, "Operation Code")) {
            CHECK_INTEGER_OR_STRING_TYPE(value, "DHCPv4");
            
            if(value->type == json_integer) {
                anubis_parse_byte_integer("DHCPv4", name, value, &dhcp_hdr->dhcp_opcode, &op);
                continue;
            }//end if
            
#define DHCP_REQUEST 0x1
#define DHCP_REPLY   0x2
            COMPARE_DEFINE(value->u.string.ptr, DHCP_REQUEST, dhcp_hdr->dhcp_opcode, op)
            else
                COMPARE_DEFINE(value->u.string.ptr, DHCP_REPLY, dhcp_hdr->dhcp_opcode, op)
            else
                anubis_parse_byte_integer("DHCPv4", name, value, &dhcp_hdr->dhcp_opcode, &op);
        }//end if
        else if(!strcasecmp(name, "Hardware Address Type")) {
            anubis_parse_byte_integer("DHCPv4", name, value, &dhcp_hdr->dhcp_htype, NULL);
        }//end if
        else if(!strcasecmp(name, "Hardware Address Length")) {
            anubis_parse_byte_integer("DHCPv4", name, value, &dhcp_hdr->dhcp_hlen, NULL);
        }//end if
        else if(!strcasecmp(name, "Hops")) {
            anubis_parse_byte_integer("DHCPv4", name, value, &dhcp_hdr->dhcp_hopcount, NULL);
        }//end if
        else if(!strcasecmp(name, "Transaction ID")) {
            if(value->type == json_string && IS_RANDOM(value->u.string.ptr))
                dhcp_hdr->dhcp_xid = anubis_random(value->u.string.ptr);
            else
                anubis_parse_4bytes_integer("DHCPv4", name, value, &dhcp_hdr->dhcp_xid, NULL);
        }//end if
        else if(!strcasecmp(name, "Seconds")) {
            anubis_parse_2bytes_integer("DHCPv4", name, value, &dhcp_hdr->dhcp_secs, NULL);
        }//end if
        else if(!strcasecmp(name, "Broadcast Flags")) {
            int enable_flags = 0;
            anubis_parse_boolean("DHCPv4", name, value, &enable_flags, NULL);
            dhcp_hdr->dhcp_flags = enable_flags << 15;
        }//end if
        else if(!strcasecmp(name, "Client IP Address")) {
            anubis_parse_ip_address("DHCPv4", name, value, &dhcp_hdr->dhcp_cip, sizeof(dhcp_hdr->dhcp_cip), device, NULL);
        }//end if
        else if(!strcasecmp(name, "Your IP Address")) {
            anubis_parse_ip_address("DHCPv4", name, value, &dhcp_hdr->dhcp_yip, sizeof(dhcp_hdr->dhcp_yip), device, NULL);
        }//end if
        else if(!strcasecmp(name, "Server IP Address")) {
            anubis_parse_ip_address("DHCPv4", name, value, &dhcp_hdr->dhcp_sip, sizeof(dhcp_hdr->dhcp_sip), device, NULL);
        }//end if
        else if(!strcasecmp(name, "Gateway IP Address")) {
            anubis_parse_ip_address("DHCPv4", name, value, &dhcp_hdr->dhcp_gip, sizeof(dhcp_hdr->dhcp_gip), device, NULL);
        }//end if
        else if(!strcasecmp(name, "Client MAC Address")) {
            anubis_parse_mac_address("DHCPv4", name, value, (u_int8_t *)&dhcp_hdr->dhcp_chaddr, dhcp_hdr->dhcp_hlen, device, NULL);
        }//end if
        else if(!strcasecmp(name, "Server Hostname")) {
            char *server_hostname = NULL;
            anubis_parse_string("DHCPv4", name, value, &server_hostname, NULL);
            if(!server_hostname)
                continue;
            if(strlen(server_hostname) > sizeof(dhcp_hdr->dhcp_sname)) {
                anubis_err("DHCPv4: \"Server Hostname\" length maximum is %d\n", (int)sizeof(dhcp_hdr->dhcp_sname) - 1);
                continue;
            }
            memset(dhcp_hdr->dhcp_sname, 0, sizeof(dhcp_hdr->dhcp_sname));
            memmove(dhcp_hdr->dhcp_sname, server_hostname, strlen(server_hostname));
        }//end if
        else if(!strcasecmp(name, "Boot File Name")) {
            char *boot_filename = NULL;
            anubis_parse_string("DHCPv4", name, value, &boot_filename, NULL);
            if(!boot_filename)
                continue;
            if(strlen(boot_filename) > sizeof(dhcp_hdr->dhcp_file)) {
                anubis_err("DHCPv4: \"Boot File Name\" length maximum is %d\n", (int)sizeof(dhcp_hdr->dhcp_file) - 1);
                continue;
            }
            memset(dhcp_hdr->dhcp_file, 0, sizeof(dhcp_hdr->dhcp_file));
            memmove(dhcp_hdr->dhcp_file, boot_filename, strlen(boot_filename));
        }//end if
        else {
            anubis_err("DHCPv4: \"%s\" unknown field\n", name);
        }//end else
    }
    
    CHECK_REQUIREMENT(op, "DHCPv4", "Operation Code");
}//end anubis_parse_dhcp_hdr

void anubis_parse_dhcp_options(json_value *json, anubis_options_t *options, const char *device) {
    
    CHECK_OPTION_TYPE(json, "DHCPv4 Options");
    
    int current_len = 0;
    u_int8_t option_tmp[65535 - 20 - 8 - LIBNET_DHCPV4_H] = {0}; //maximux packet size - IP - UDP - DHCP
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
                
                CHECK_INTEGER_OR_STRING_TYPE(value, "DHCPv4 Options");
                
                if(value->type == json_integer) {
                    anubis_parse_byte_integer("DHCPv4 Options", name, value, &type, &required_type);
                    break;
                }//end if
          
#define DHCP_PAD 0x00
#define DHCP_MESSAGETYPE 0x35
#define DHCP_CLIENTID 0x3d
#define DHCP_REQUESTED_IP_ADDRESS 0x32
#define DHCP_PARAMREQUEST 0x37
#define DHCP_END 0xff
#define DHCP_SERVER 0x36
#define DHCP_LEASETIME 0x33
#define DHCP_SUBNETMASK 0x01
#define DHCP_ROUTER 0x03
#define DHCP_DNS_SERVER 0x06
#define DHCP_NTP_SERVER 0x2a
#define DHCP_RENEWTIME 0x3a
#define DHCP_REBINDTIME 0x3b
#define DHCP_HOSTNAME 0x0c
                char *ptr = value->u.string.ptr;
                COMPARE_DEFINE(ptr, DHCP_MESSAGETYPE, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_CLIENTID, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_REQUESTED_IP_ADDRESS, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_PARAMREQUEST, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_END, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_PAD, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_SERVER, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_LEASETIME, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_SUBNETMASK, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_ROUTER, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_DNS_SERVER, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_NTP_SERVER, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_RENEWTIME, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_REBINDTIME, type, required_type)
                else
                    COMPARE_DEFINE(ptr, DHCP_HOSTNAME, type, required_type)
                else
                    anubis_parse_byte_integer("DHCPv4 Options", name, value, &type, &required_type);
                
                break;
            }//end if
        }//end for
        
        //set type failure
        CHECK_REQUIREMENT(required_type, "DHCPv4 Options", "Type");
        if(!required_type)
            continue;
        
        char prefix_type[ANUBIS_BUFFER_SIZE] = {0};
        snprintf(prefix_type, sizeof(prefix_type), "DHCPv4 Options: Type(%d)", type);
        
        switch (type) {
            case DHCP_MESSAGETYPE:
            {
                u_int8_t length = 1;
                u_int8_t message = 0;
                int required_message = 0;
                
                //parse
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }//end if
                    else if(!strcasecmp(name, "Message")) {
                        
                        CHECK_INTEGER_OR_STRING_TYPE(value, "DHCPv4 Options");
                        
                        if(value->type == json_integer) {
                            anubis_parse_byte_integer(prefix_type, name, value, &message, &required_message);
                            break;
                        }//end if
                 
#define DHCP_MSGDISCOVER     0x01
#define DHCP_MSGOFFER        0x02
#define DHCP_MSGREQUEST      0x03
#define DHCP_MSGDECLINE      0x04
#define DHCP_MSGACK          0x05
#define DHCP_MSGNACK         0x06
#define DHCP_MSGRELEASE      0x07
#define DHCP_MSGINFORM       0x08
                        COMPARE_DEFINE(value->u.string.ptr, DHCP_MSGDISCOVER, message, required_message)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_MSGOFFER, message, required_message)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_MSGREQUEST, message, required_message)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_MSGDECLINE, message, required_message)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_MSGACK, message, required_message)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_MSGNACK, message, required_message)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_MSGRELEASE, message, required_message)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_MSGINFORM, message, required_message)
                        else
                            anubis_parse_byte_integer(prefix_type, name, value, &type, &required_message);
                        
                    }//end if
                    else if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//else
                }//end for
                
                
                CHECK_REQUIREMENT(required_message, prefix_type, "Message");
                
                option_tmp[current_len++] = type;
                option_tmp[current_len++] = length;
                memmove(option_tmp + current_len, &message, length);
                current_len += length;
            }//end case message
                break;
                
            case DHCP_CLIENTID:
            {
                u_int8_t length = 7;
                u_int8_t htype = 0x1;
                u_int8_t *client_address = anubis_default_mac_address(device);
                
                //parse
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }//end if
                    else if(!strcasecmp(name, "Hardware Address Type")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &htype, NULL);
                    }//end if
                    else if(!strcasecmp(name, "Client Hardware Address")) {
                        if(value->type == json_string && !strcasecmp(value->u.string.ptr, "myself"))
                            continue;
                        anubis_parse_mac_address(prefix_type, name, value, client_address, length - 1, device, NULL);
                    }
                    else if(!strcasecmp(name, "type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//else
                    
                }//for
                
                option_tmp[current_len++] = type;
                option_tmp[current_len++] = length;
                option_tmp[current_len++] = htype;
                memmove(option_tmp + current_len, client_address, length - 1);
                current_len += length - 1;
            }//end case client id
                break;
                
            case DHCP_PARAMREQUEST:
            {
                u_int8_t length = 0;
                json_value *list = NULL;
                
                //get length first
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }//end if
                    else if(!strcasecmp(name, "List")) {
                        if(value->type != json_array)
                            anubis_err("%s: should be an array\n", prefix_type);
                        else
                            list = value;
                    }//end if
                }//end for
                
                CHECK_REQUIREMENT(list, prefix_type, "List");
                if(!list)
                    continue;
                
                if(length == 0)
                    length = list->u.array.length;
                
                option_tmp[current_len++] = type;
                option_tmp[current_len++] = length;
                
                for(int j = 0 ; j < list->u.array.length && j < length ; j++) {
                    json_value *value = list->u.array.values[j];
                    char *name = "List";
                    u_int8_t item = 0;
                    
                    CHECK_INTEGER_OR_STRING_TYPE(value, prefix_type);
                    
                    if(value->type == json_integer) {
                        anubis_parse_byte_integer(prefix_type, name, value, &item, NULL);
                    }//end if
                    else {
                        int tmp;
                        COMPARE_DEFINE(value->u.string.ptr, DHCP_SUBNETMASK, item, tmp)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_ROUTER, item, tmp)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_DNS_SERVER, item, tmp)
                        else
                            COMPARE_DEFINE(value->u.string.ptr, DHCP_NTP_SERVER, item, tmp)
                        else
                            anubis_parse_byte_integer(prefix_type, name, value, &item, NULL);
                    }//end else
                    
                    //if(item) {
                        option_tmp[current_len++] = item;
                    //}
                }//end for
            }//end case
                break;
                
            case DHCP_END:
                //parse
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    
                    if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//end if
                }//end for
                option_tmp[current_len++] = 0xff;
                break;
                
            case DHCP_PAD:
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    
                    if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//end if
                }//end for
                option_tmp[current_len++] = 0x00;
                break;
                
            case DHCP_LEASETIME:
            case DHCP_RENEWTIME:
            case DHCP_REBINDTIME:
            {
                u_int8_t length = 4;
                u_int32_t time = 0;
                int required_time = 0;
                
                //parse
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }//end if
                    else if(!strcasecmp(name, "Time")) {
                        anubis_parse_4bytes_integer(prefix_type, name, value, &time, &required_time);
                        time = htonl(time);
                    }
                    else if(!strcasecmp(name, "type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//else
                }//end for
                
                CHECK_REQUIREMENT(required_time, prefix_type, "Time");
                
                option_tmp[current_len++] = type;
                option_tmp[current_len++] = length;
                memmove(option_tmp + current_len, &time, length);
                current_len += length;
            }
                break;
                
            case DHCP_SERVER:
            case DHCP_SUBNETMASK:
            case DHCP_ROUTER:
            case DHCP_DNS_SERVER:
            case DHCP_NTP_SERVER:
            case DHCP_REQUESTED_IP_ADDRESS:
            {
                u_int8_t length = 4;
                in_addr_t address = 0;
                int required = 0;
                
                //parse
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }//end if
                    else if(type == DHCP_REQUESTED_IP_ADDRESS && !strcasecmp(name, "Requested IP Address")) {
                        anubis_parse_ip_address(prefix_type, name, value, &address, sizeof(address), device, NULL);
                    }
                    else if(type == DHCP_SERVER && !strcasecmp(name, "Server IP Address")) {
                        anubis_parse_ip_address(prefix_type, name, value, &address, sizeof(address), device, &required);
                    }
                    else if(type == DHCP_SUBNETMASK && !strcasecmp(name, "Netmask")) {
                        anubis_parse_ip_address(prefix_type, name, value, &address, sizeof(address), device, &required);
                    }
                    else if(type == DHCP_ROUTER && !strcasecmp(name, "Router IP Address")) {
                        anubis_parse_ip_address(prefix_type, name, value, &address, sizeof(address), device, &required);
                    }
                    else if(type == DHCP_DNS_SERVER && !strcasecmp(name, "DNS IP Address")) {
                        anubis_parse_ip_address(prefix_type, name, value, &address, sizeof(address), device, &required);
                    }
                    else if(type == DHCP_NTP_SERVER && !strcasecmp(name, "NTP IP Address")) {
                        anubis_parse_ip_address(prefix_type, name, value, &address, sizeof(address), device, &required);
                    }
                    else if(!strcasecmp(name, "type")) {
                        
                    }//end if
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//else
                }//end for
                
                switch (type) {
                    case DHCP_SERVER: CHECK_REQUIREMENT(required, prefix_type, "Server IP Address"); break;
                    case DHCP_SUBNETMASK: CHECK_REQUIREMENT(required, prefix_type, "Netmask"); break;
                    case DHCP_ROUTER: CHECK_REQUIREMENT(required, prefix_type, "Router IP Address"); break;
                    case DHCP_DNS_SERVER: CHECK_REQUIREMENT(required, prefix_type, "DNS IP Address"); break;
                    case DHCP_NTP_SERVER: CHECK_REQUIREMENT(required, prefix_type, "NTP IP Address"); break;
                }
                
                option_tmp[current_len++] = type;
                option_tmp[current_len++] = length;
                memmove(option_tmp + current_len, &address, sizeof(address));
                current_len += length;
            }//end case
                break;
                
            case DHCP_HOSTNAME:
            {
                u_int8_t orig_length = 0;
                u_int8_t length = 0;
                int required_hostname = 0;
                char *hostname = NULL;
                for(int j = 0 ; j < option_object->u.object.length ; j++) {
                    json_char *name = option_object->u.object.values[j].name;
                    json_value *value = option_object->u.object.values[j].value;
                    
                    if(!strcasecmp(name, "Type")) {
                        
                    }//end if
                    else if(!strcasecmp(name, "Hostname")) {
                        anubis_parse_string(prefix_type, name, value, &hostname, &required_hostname);
                        if(!hostname)
                            continue;
                        orig_length = value->u.string.length;
                    }//end else
                    else if(!strcasecmp(name, "Length")) {
                        anubis_parse_byte_integer(prefix_type, name, value, &length, NULL);
                    }
                    else {
                        anubis_err("%s: \"%s\": unknown field\n", prefix_type, name);
                    }//end if
                }//end for
                
                if(length == 0)
                    length = orig_length;
                
                CHECK_REQUIREMENT(required_hostname, prefix_type, "Hostname");
                if(!required_hostname)
                    continue;
                
                option_tmp[current_len++] = type;
                option_tmp[current_len++] = length;
                memmove(option_tmp + current_len, hostname, length);
                current_len += length;
                
            }//end case
                break;
                
            default:
                anubis_err("DHCPv4 Options: \"%d\" unknown DHCP option\n", type);
                continue; //next loop
        }//end switch
        
        //reach max dhcp option len
        if(current_len >= sizeof(option_tmp)) {
            anubis_verbose("DHCPv4 Options: Reach maximum option length: %d bytes\n", (int)sizeof(option_tmp));
            break;
        }//end if
    }//end for
    
    //copy data
    if(current_len == 0)
        return;
    
    /*RFC1542: The IP Total Length and UDP Length must be large enough to contain the minimal BOOTP header of 300 octets*/
    int auto_padding = 0;
    if (current_len + LIBNET_DHCPV4_H < LIBNET_BOOTP_MIN_LEN) {
        anubis_verbose("DHCPv4 Options: Before option length: %d bytes\n", current_len);
        anubis_verbose("DHCPv4 Options: Auto padding %d byte%s",
                       LIBNET_BOOTP_MIN_LEN - LIBNET_DHCPV4_H - current_len,
                       LIBNET_BOOTP_MIN_LEN - LIBNET_DHCPV4_H - current_len == 0 ? "\n" : "s\n");
        memset(option_tmp + current_len, 0, LIBNET_BOOTP_MIN_LEN - LIBNET_DHCPV4_H - current_len);
        current_len = LIBNET_BOOTP_MIN_LEN - LIBNET_DHCPV4_H;
        auto_padding = 1;
    }//end if
    
    options->options_length = current_len < sizeof(option_tmp) ? current_len : sizeof(option_tmp);
    options->options = (u_int8_t *)malloc(options->options_length);
    if(!options->options) {
        anubis_perror("malloc()");
        return;
    }//end if
    memmove(options->options, option_tmp, options->options_length);
    
    if(auto_padding) { //after padding
        anubis_verbose("DHCPv4 Options: After option length: %d bytes\n", current_len);
    }
    else {
        anubis_verbose("DHCPv4 Options: Option length: %d bytes\n", current_len);
    }
}//end anubis_parse_dhcp_option

void anubis_parse_raw_data(json_value *json, anubis_packet_raw_data_t *raw_data) {
    CHECK_HEADER_TYPE(json, "Raw Data");
    
    int required_data = 0;
    u_int16_t length = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Data")) {
            anubis_parse_string("Raw Data", name, value, (char **)&raw_data->data, &required_data);
            if(!raw_data->data)
                continue;
            length = value->u.string.length;
        }//end if
        else if(!strcasecmp(name, "Data length")) {
            anubis_parse_2bytes_integer("Raw Data", name, value,
                                        &raw_data->data_length, NULL);
        }//end if
        else {
            anubis_err("Raw Data: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    if(raw_data->data_length == 0)
        raw_data->data_length = length;
    
    CHECK_REQUIREMENT(required_data, "Raw Data", "Data");
}//end anubis_parse_raw_data

void anubis_parse_payload(json_value *json, anubis_packet_raw_data_t *payload) {
    
    CHECK_HEADER_TYPE(json, "Payload");
    
    int required_payload = 0;
    u_int16_t length = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Payload")) {
            anubis_parse_string("Raw Data", name, value, (char **)&payload->data, &required_payload);
            if(!payload->data)
                continue;
            length = value->u.string.length;
        }//end if
        else if(!strcasecmp(name, "Payload length")) {
            anubis_parse_2bytes_integer("Payload", name, value,
                                        &payload->data_length, NULL);
        }//end if
        else {
            anubis_err("Payload: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    if(payload->data_length == 0)
        payload->data_length = length;
    
    CHECK_REQUIREMENT(required_payload, "Payload", "Payload");
}//end anubis_parse_payload
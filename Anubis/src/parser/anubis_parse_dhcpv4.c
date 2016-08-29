//
//  anubis_parse_dhcpv4.c
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

void anubis_parse_dhcp_hdr(json_value *json, struct libnet_dhcpv4_hdr *dhcp_hdr, const char *device) {
    CHECK_OBJECT_TYPE(json, "DHCPv4", "DHCPv4");
    
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
    
    CHECK_ARRAY_TYPE(json, "DHCPv4 Options", "DHCPv4 Options");
    
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

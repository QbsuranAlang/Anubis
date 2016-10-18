//
//  anubis_parse_tcp.c
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

void anubis_parse_tcp_hdr(json_value *json, struct libnet_tcp_hdr *tcp_hdr) {
    
    CHECK_OBJECT_TYPE(json, "TCP", "TCP");
    
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
    
    CHECK_ARRAY_TYPE(json, "TCP Options", "TCP Options");
    
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

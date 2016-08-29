//
//  anubis_parse_socket.c
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

#define APPEND_PACKET(x) { \
    if(x->packets) { \
        anubis_packet_t *temp = (anubis_packet_t *)realloc(x->packets, sizeof(anubis_packet_t) * (x->packets_count + 1)); \
        if(!temp) { \
            anubis_perror("realloc()"); \
            continue; \
        } \
        x->packets = temp; \
        memset(&x->packets[x->packets_count], 0, sizeof(x->packets[x->packets_count])); \
    } \
    else { \
        x->packets = (anubis_packet_t *)malloc(sizeof(anubis_packet_t)); \
        if(!x->packets) { \
            anubis_perror("malloc()"); \
            continue; \
        } \
    memset(x->packets, 0, sizeof(anubis_packet_t)); \
    } \
    x->packets_count++; \
}

#define APPEND_HEADER(x, proto, header) { \
    if(x.protocols) {  \
        anubis_protocol_t *temp = (anubis_protocol_t *)realloc(x.protocols, sizeof(anubis_protocol_t) * (x.layers + 1)); \
        if(!temp) { \
            anubis_perror("realloc()"); \
            continue; \
        } \
        x.protocols = temp; \
        memset(&x.protocols[x.layers], 0, sizeof(x.protocols[x.layers])); \
    } \
    else { \
        x.protocols = (anubis_protocol_t *)malloc(sizeof(anubis_protocol_t)); \
        if(!x.protocols) { \
            anubis_perror("malloc()"); \
            continue; \
        } \
        memset(x.protocols, 0, sizeof(sizeof(anubis_protocol_t))); \
    } \
    x.protocols[x.layers].protocol_type = proto; \
    memmove(&x.protocols[x.layers].u, &header, sizeof(x.protocols[x.layers].u)); \
    x.layers++; \
}

#pragma mark parse config
static int anubis_check_config_requirement(anubis_t *config) {
    
    if(!config->device &&
       ((config->socket_type == anubis_data_link_socket ||
         config->socket_type == anubis_network_socket))) {
        
        config->device = anubis_default_device();
        if(!config->device)
            return -1;
        else {
            config->device = strdup(config->device);
            if(!config->device)
                anubis_perror("strdup()");
        }//end else
        return 0;
    }//end if
    
    
    if(config->socket_type == anubis_data_link_socket) {
        
    }//end if data-link
    else if(config->socket_type == anubis_network_socket) {
        
    }//end if network
    else if(config->socket_type == anubis_transport_socket) {
        if(!config->dst_ip) {
            anubis_err("\"Destination IP Address\" is required\n");
            return -1;
        }//end if
        
        if(!config->protocol) {
            anubis_err("\"Protocol\" is required\n");
            return -1;
        }//end if
        
    }//end if transport
    else if(config->socket_type == anubis_application_socket) {
        if(!config->type) {
            anubis_err("\"Type\" is required\n");
            return -1;
        }//end if
        
        if(config->role != ANUBIS_ROLE_SERVER &&
           config->role != ANUBIS_ROLE_CLIENT) {
            anubis_err("\"Role\" is required\n");
            return -1;
        }//end if
        
        if(config->role == ANUBIS_ROLE_CLIENT) {
            if(!config->dst_ip) {
                anubis_err("\"Destination IP Address\" is required\n");
                return -1;
            }//end if
            if(!config->dst_port) {
                anubis_err("\"Destination Port\" is required\n");
                return -1;
            }//end if
        }//end if
        else if(config->role == ANUBIS_ROLE_SERVER) {
            if(!config->src_port) {
                anubis_err("\"Source Port\" is required\n");
                return -1;
            }//end if
            if(config->type == SOCK_STREAM) {
                if(!config->max_connection) {
                    anubis_err("\"Max Connection\" is required\n");
                    return -1;
                }
                if(config->security_socket) {
                    if(!config->sslMethod) {
                        anubis_err("\"Method\" is required\n");
                        return -1;
                    }
                    if(!config->certificate_file) {
                        anubis_err("\"Certificate\" is required\n");
                        return -1;
                    }
                    struct stat filestatus = {0};
                    //check file exsit or not
                    if (stat(config->certificate_file, &filestatus) != 0 && errno == ENOENT) {
                        anubis_err("\"Certificate\": \"%s\" is not exsit\n", config->certificate_file);
                        ;//return -1;
                    }//end if
                    
                    if(!config->private_key_file) {
                        anubis_err("\"Private key\" is required\n");
                        return -1;
                    }
                    
                    //check file exsit or not
                    if (stat(config->private_key_file, &filestatus) != 0 && errno == ENOENT) {
                        anubis_err("\"Private key\": \"%s\" is not exsit\n", config->private_key_file);
                        return -1;
                    }//end if
                }
                
            }//end if is SOCK_STREAM
        }//end if
    }//end if
    
    if(config->sequence_length <= 0 || !config->sequence_data) {
        anubis_err("\"Sequence\" is required\n");
        return -1;
    }//end if
    
    return 0;
}//end anubis_check_config_requirement

static void anubis_parse_send_packet_option(json_value *json, anubis_socket_type socket_type, const char *device, anubis_packet_t *packet) {
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(socket_type == anubis_data_link_socket ||
           socket_type == anubis_network_socket ||
           socket_type == anubis_transport_socket) {
            if(!strcasecmp(name, "Infinite loop")) {
                anubis_parse_boolean("Packet Option", name, value, &packet->infinite_loop, NULL);
            }//end if
            else if(!strcasecmp(name, "Interval")) {
                anubis_parse_4bytes_integer("Packet Option", name, value, &packet->interval, NULL);
            }//end if
            else if(!strcasecmp(name, "Amount")) {
                anubis_parse_4bytes_integer("Packet Option", name, value, &packet->amount, NULL);
            }//end if
            else if(!strcasecmp(name, "Dump send packet")) {
                anubis_parse_boolean("Packet Option", name, value, &packet->dump_send, NULL);
            }//end if
            else if(!strcasecmp(name, "Input from file")) {
                anubis_parse_string("Packet Option", name, value, &packet->input_filename, NULL);
                if(!packet->input_filename)
                    continue;
                packet->input_filename = strdup(packet->input_filename);
                if(!packet->input_filename) {
                    anubis_perror("strdup()");
                    continue;
                }
            }
            else {
                anubis_err("Packet Option: \"%s\" unknown key\n", name);
            }//end else
        }//end if data-link network transport
        else if(socket_type == anubis_application_socket) {
            if(!strcasecmp(name, "Infinite loop")) {
                anubis_parse_boolean("Packet Option", name, value, &packet->infinite_loop, NULL);
            }//end if
            else if(!strcasecmp(name, "Interval")) {
                anubis_parse_4bytes_integer("Packet Option", name, value, &packet->interval, NULL);
            }//end if
            else if(!strcasecmp(name, "Amount")) {
                anubis_parse_4bytes_integer("Packet Option", name, value, &packet->amount, NULL);
            }//end if
            else if(!strcasecmp(name, "Dump send packet")) {
                anubis_parse_boolean("Packet Option", name, value, &packet->dump_send, NULL);
            }//end if
            else if(!strcasecmp(name, "Send Timeout")) {
                anubis_parse_4bytes_integer("Packet Option", name, value, &packet->send_timeout, NULL);
            }//end if
            else if(!strcasecmp(name, "Send Length")) {
                anubis_parse_2bytes_integer("Packet Option", name, value, &packet->send_length, NULL);
            }//end if
            else if(!strcasecmp(name, "Interactive")) {
                anubis_parse_boolean("Packet Option", name, value, &packet->interactive, NULL);
            }//end if
            else if(!strcasecmp(name, "Input from file")) {
                anubis_parse_string("Packet Option", name, value, &packet->input_filename, NULL);
                if(!packet->input_filename)
                    continue;
                
                struct stat filestatus = {0};
                //check file exsit or not
                if (stat(packet->input_filename, &filestatus) != 0 && errno == ENOENT) {
                    anubis_err("Packet Option: \"%s\" is not exsit\n", packet->input_filename);
                    packet->input_filename = NULL;
                    continue;
                }//end if
                
                packet->input_filename = strdup(packet->input_filename);
                if(!packet->input_filename) {
                    anubis_perror("strdup()");
                    continue;
                }
            }
            else {
                anubis_err("Packet Option: \"%s\" unknown key\n", name);
            }//end else
        }//end if application
    }//end for
    
    if(packet->input_filename && packet->interactive) {
        anubis_err("Packet Option: \"Input from file\" and \"Interactive\" should not be appear at the same time\n");
        anubis_err("Packet Option: \"Interactive\" is disabled\n");
        packet->interactive = 0;
    }//end if
    
}//end anubis_parse_send_packet_option

static void anubis_parse_receive_packet_option(json_value *json, anubis_socket_type socket_type, const char *device, anubis_packet_t *packet) {
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Infinite loop")) {
            anubis_parse_boolean("Packet Option", name, value, &packet->infinite_loop, NULL);
        }//end if
        else if(!strcasecmp(name, "Interval")) {
            anubis_parse_4bytes_integer("Packet Option", name, value, &packet->interval, NULL);
        }//end if
        else if(!strcasecmp(name, "Amount")) {
            anubis_parse_4bytes_integer("Packet Option", name, value, &packet->amount, NULL);
        }//end if
        else if(!strcasecmp(name, "Dump receive packet")) {
            anubis_parse_boolean("Packet Option", name, value, &packet->dump_recv, NULL);
        }//end if
        else if(!strcasecmp(name, "Receive Timeout")) {
            anubis_parse_4bytes_integer("Packet Option", name, value, &packet->recv_timeout, NULL);
        }//end if
        else if(!strcasecmp(name, "Read until Timeout")) {
            anubis_parse_boolean("Packet Option", name, value, &packet->read_until_timeout, NULL);
        }//end if
        else if(!strcasecmp(name, "Output to file")) {
            anubis_parse_string("Packet Option", name, value, &packet->output_filename, NULL);
            if(!packet->output_filename)
                continue;
            packet->output_filename = strdup(packet->output_filename);
            if(!packet->output_filename) {
                anubis_perror("strdup()");
                continue;
            }
        }
        else {
            anubis_err("Packet Option: \"%s\" unknown key\n", name);
        }//end else
    }//end for
    
    //need infinite loop to keep reading
    if(packet->read_until_timeout)
        packet->infinite_loop = 1;
}//end anubis_parse_receive_packet_option

#pragma mark parse socket config and headers
static void anubis_parse_socket_config(json_value *json, anubis_t *config) {
    
    char *prefix = "";
    
    switch (config->socket_type) {
        case anubis_data_link_socket:
            prefix = "Data-link";
            break;
            
        case anubis_network_socket:
            prefix = "Network";
            break;
            
        case anubis_transport_socket:
            prefix = "Transport";
            break;
            
        case anubis_application_socket:
            prefix = "Applcation";
            break;
            
        default:
            anubis_err("anubis_parse_socket_config(): It is never should be happened\n");
            return;
    }//end switch
    
    //read common options
    anubis_verbose("Socket[%d] Start parsing %s option\n", config->index, prefix);
    json_value *options = NULL;
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "_comment")) {
            if(value->type == json_string && value->u.string.length == 0)
                continue;
            anubis_parse_string(prefix, name, value, &config->comment, NULL);
            if(!config->comment)
                continue;
            config->comment = strdup(config->comment);
            if(!config->comment) {
                anubis_perror("strdup()");
                continue;
            }//end if
        }//end if comment
        else if(!strcasecmp(name, "Sequence")) {
            if(value->type != json_array) {
                anubis_err("%s: \"%s\" should be an array\n", prefix, name);
                continue;
            }//end if
            
            config->sequence_length = value->u.array.length;
            config->sequence_data = value->u.array.values;
        }//end if
        else if(!strcasecmp(name, "Socket-type")) {
            
        }//end if socket_type
        else if(!strcasecmp(name, "Option")) {
            options = value;
        }//end if
        else {
            anubis_err("%s: \"%s\" unknown key\n", name, prefix);
        }//end else
    }//end for
    
    CHECK_REQUIREMENT(options, prefix, "Option");
    if(!options)
        return;
    CHECK_OBJECT_TYPE(options, prefix, "Option");
    
    //read device and application type first
    for(int i = 0 ; i < options->u.object.length ;i++) {
        json_char *name = options->u.object.values[i].name;
        json_value *value = options->u.object.values[i].value;
        
        if(!strcasecmp(name, "Device")) {
            anubis_parse_string(prefix, name, value, &config->device, NULL);
            if(!config->device)
                continue;
            config->device = strdup(config->device);
            if(!config->device) {
                anubis_perror("strdup()");
                continue;
            }//end if
        }//end if device
        else if(config->socket_type == anubis_application_socket &&
                !strcasecmp(name, "Type")) {
            
            if(value->type != json_string) {
                anubis_err("%s: \"%s\" should be a string\n", prefix, name);
                continue;
            }//end if
            
            int required_type;
            COMPARE_DEFINE(value->u.string.ptr, SOCK_STREAM, config->type, required_type)
            else
                COMPARE_DEFINE(value->u.string.ptr, SOCK_DGRAM, config->type, required_type)
                else
                    anubis_err("%s: \"%s\" should be \"SOCK_STREAM\" or \"SOCK_DGRAM\" only\n", prefix, name);
            
#pragma mark security default value
            if(config->type == SOCK_STREAM) {
                config->max_connection = 1024;
                config->sslMethod = strdup("SSLv23");
                if(!config->sslMethod) {
                    anubis_perror("strdup()");
                    continue;
                }//end if
            }
            else if(config->type == SOCK_DGRAM) {
                config->sslMethod = strdup("DTLS");
                if(!config->sslMethod) {
                    anubis_perror("strdup()");
                    continue;
                }//end if
            }
        }//end if
        else if(config->socket_type == anubis_application_socket &&
                !strcasecmp(name, "Security")) {
            anubis_parse_boolean(prefix, name, value, &config->security_socket, NULL);
        }//end if
        else if(config->socket_type == anubis_application_socket &&
                !strcasecmp(name, "Role")) {
            if(value->type != json_string) {
                anubis_err("%s: \"%s\" should be a string\n", prefix, name);
                continue;
            }//end if
            
            if(!strcasecmp(value->u.string.ptr, "Server")) {
                config->role = ANUBIS_ROLE_SERVER;
            }//end if
            else if(!strcasecmp(value->u.string.ptr, "Client")) {
                config->role = ANUBIS_ROLE_CLIENT;
            }//end if
            else
                anubis_err("%s: \"%s\" should be \"Server\" or \"Client\" only\n", prefix, name);
        }//end if
    }//end for
    
    /*libnet on windows not accept NULL device*/
#ifdef __CYGWIN__
    if (!config->device) {
        config->device = anubis_default_device();
        if (config->device) {
            config->device = strdup(config->device);
            if (!config->device)
                anubis_perror("strdup()");
        }//end if
    }//end if
#endif
    
    for(int i = 0 ; i < options->u.object.length ;i++) {
        json_char *name = options->u.object.values[i].name;
        json_value *value = options->u.object.values[i].value;
        
        if(!strcasecmp(name, "Device") || !strcasecmp(name, "Type") ||
           !strcasecmp(name, "Security") || !strcasecmp(name, "Role") ||
           !strcasecmp(name, "_comment")) {
            
        }//end if
        else if(!strcasecmp(name, "Infinite loop")) {
            anubis_parse_boolean(prefix, name, value, &config->infinite_loop, NULL);
        }//end if
        else if(!strcasecmp(name, "Interval")) {
            anubis_parse_4bytes_integer(prefix, name, value, &config->interval, NULL);
        }//end if
        else if(!strcasecmp(name, "Amount")) {
            anubis_parse_4bytes_integer(prefix, name, value, &config->amount, NULL);
        }//end if
        
        /*Transport*/
        else if(config->socket_type == anubis_transport_socket &&
                !strcasecmp(name, "Destination IP Address")) {
            anubis_parse_ip_address(prefix, name, value,
                                    (in_addr_t *)&config->dst_ip, sizeof(config->dst_ip),
                                    config->device, NULL);
        }//end if
        else if(config->socket_type == anubis_transport_socket &&
                !strcasecmp(name, "Protocol")) {
            
            int required_proto = 0;
            char *ptr = NULL;
            anubis_parse_string(prefix, name, value, &ptr, NULL);
            if(!ptr)
                continue;
            
            COMPARE_DEFINE(ptr, IPPROTO_ICMP, config->protocol, required_proto)
            else
                COMPARE_DEFINE(ptr, IPPROTO_TCP, config->protocol, required_proto)
            else
                COMPARE_DEFINE(ptr, IPPROTO_UDP, config->protocol, required_proto)
            else {
                anubis_err("%s: \"%s\" should be \"IPPROTO_TCP\", \"IPPROTO_UDP\" or \"IPPROTO_ICMP\" only\n", prefix, name);
                continue;
            }//end if
        }//end if
        
        /*Application*/
        else if(config->socket_type == anubis_application_socket &&
                !strcasecmp(name, "Destination IP Address")) {
            anubis_parse_ip_address(prefix, name, value,
                                    (in_addr_t *)&config->dst_ip, sizeof(config->dst_ip),
                                    config->device, NULL);
        }//end if
        else if(config->socket_type == anubis_application_socket &&
                !strcasecmp(name, "Destination Port")) {
            if(value->type == json_string && IS_RANDOM(value->u.string.ptr)) {
                config->dst_port = (u_int16_t)anubis_random(value->u.string.ptr);
            }//end if
            else if(value->type == json_string && IS_PORT(value->u.string.ptr)) {
                config->dst_port = anubis_port(value->u.string.ptr);
            }//end if
            else
                anubis_parse_2bytes_integer(prefix, name, value,
                                            &config->dst_port, NULL);
        }//end if
        else if(config->socket_type == anubis_application_socket &&
                !strcasecmp(name, "Source Port")) {
            if(value->type == json_string && IS_RANDOM(value->u.string.ptr)) {
                config->src_port = (u_int16_t)anubis_random(value->u.string.ptr);
            }//end if
            else if(value->type == json_string && IS_PORT(value->u.string.ptr)) {
                config->src_port = anubis_port(value->u.string.ptr);
            }//end if
            else
                anubis_parse_2bytes_integer(prefix, name, value,
                                            &config->src_port, NULL);
        }//end if
        
        else if(config->socket_type == anubis_application_socket &&
                !strcasecmp(name, "Send Timeout")) {
            anubis_parse_4bytes_integer(prefix, name, value,
                                        &config->send_timeout, NULL);
        }//end if
        else if(config->socket_type == anubis_application_socket &&
                !strcasecmp(name, "Receive Timeout")) {
            anubis_parse_4bytes_integer(prefix, name, value,
                                        &config->recv_timeout, NULL);
        }//end if
        
        /*Application SOCK_DGRAM only*/
        else if(config->socket_type == anubis_application_socket &&
                config->type == SOCK_DGRAM &&
                !strcasecmp(name, "Muliticast group")) {
            
            if(value->type != json_array) {
                anubis_err("%s: \"%s\" should be an array\n", prefix, prefix);
                continue;
            }//end if
            
            char muliticast_prefix[ANUBIS_BUFFER_SIZE] = {0};
            snprintf(muliticast_prefix, sizeof(muliticast_prefix), "%s: \"Muliticast Group\"", prefix);
            for(int j = 0 ; j < value->u.array.length; j++) {
                in_addr_t temp = 0;
                
                if(value->u.array.values[j]->type != json_string) {
                    anubis_err("%s: \"Fields\": all should be a string\n", muliticast_prefix);
                    continue;
                }//end if
                
                anubis_parse_ip_address(muliticast_prefix, name,
                                        value->u.array.values[j], &temp,
                                        sizeof(temp), config->device, NULL);
                config->muliticast_groups_length++;
                if(config->muliticast_groups) {
                    in_addr_t *realloc_temp = (in_addr_t *)realloc(config->muliticast_groups, sizeof(in_addr_t) * config->muliticast_groups_length);
                    if(!realloc_temp) {
                        anubis_perror("realloc()");
                        continue;
                    }
                    config->muliticast_groups = realloc_temp;
                }//end if
                else {
                    config->muliticast_groups = (in_addr_t *)malloc(sizeof(in_addr_t) * config->muliticast_groups_length);
                }//end else
                
                memset(&config->muliticast_groups[config->muliticast_groups_length - 1], 0,
                       sizeof(config->muliticast_groups[config->muliticast_groups_length - 1]));
                
                config->muliticast_groups[config->muliticast_groups_length - 1] = temp;
            }//end for
            
        }//end if
        
        else if(config->socket_type == anubis_application_socket &&
                (config->type == SOCK_STREAM || (config->type == SOCK_DGRAM && config->security_socket)) &&
                !strcasecmp(name, "Asynchronous")) {
            anubis_parse_boolean(prefix, name, value, &config->asynchronous, NULL);
        }//end if
        
        /*Application SOCK_STREAM only*/
        else if(config->socket_type == anubis_application_socket &&
                config->type == SOCK_STREAM &&
                !strcasecmp(name, "Max Connection")) {
            anubis_parse_2bytes_integer(prefix, name, value, &config->max_connection, NULL);
        }//end if
        
        /*Security socket is on*/
        else if(config->socket_type == anubis_application_socket &&
                config->security_socket &&
                !strcasecmp(name, "Method")) {
            
            if(config->sslMethod)
                free(config->sslMethod);
            config->sslMethod = NULL;
            anubis_parse_string(prefix, name, value, &config->sslMethod, NULL);
            if(!config->sslMethod)
                continue;
            
            config->sslMethod = strdup(config->sslMethod);
            if(!config->sslMethod) {
                anubis_perror("strdup()");
                continue;
            }//end if
            
            char *availableMethod[] = {"SSLv2", "SSLv3", "SSLv23",
                "TLSv1.0", "TLSv1.1", "TLSv1.2",
                "DTLS", "DTLS1.0", "DTLS1.2"};
            
            int found = 0;
            for(int j = 0 ; j < sizeof(availableMethod)/sizeof(*availableMethod) ; j++) {
                if(!strcasecmp(availableMethod[j], config->sslMethod)) {
                    found = 1; //found in availabe method array
                    break;
                }//end if found
            }//end for
            
            //tcp can't not use DTLS, udp can't not use SSL/TLS
            if((config->type == SOCK_STREAM && !strncasecmp(config->sslMethod, "D", 1)) ||
               (config->type == SOCK_DGRAM && strncasecmp(config->sslMethod, "D", 1))) {
                found = 0;
            }//end if
            
            if(!found) {
                anubis_err("%s: \"Method\": \"%s\" unknown SSL method\n", prefix, config->sslMethod);
                free(config->sslMethod);
                config->sslMethod = NULL;
            }//end if
        }
        else if(config->socket_type == anubis_application_socket &&
                config->security_socket &&
                !strcasecmp(name, "Certificate")) {
            anubis_parse_string(prefix, name, value, &config->certificate_file, NULL);
            if(!config->certificate_file)
                continue;
            config->certificate_file = strdup(config->certificate_file);
            if(!config->certificate_file) {
                anubis_perror("strdup()");
                continue;
            }
        }//end if
        else if(config->socket_type == anubis_application_socket &&
                config->security_socket &&
                !strcasecmp(name, "Private key")) {
            anubis_parse_string(prefix, name, value, &config->private_key_file, NULL);
            if(!config->private_key_file)
                continue;
            config->private_key_file = strdup(config->private_key_file);
            if(!config->private_key_file) {
                anubis_perror("strdup()");
                continue;
            }
        }
        else if(config->socket_type == anubis_application_socket &&
                config->security_socket &&
                config->role == ANUBIS_ROLE_CLIENT &&
                !strcasecmp(name, "Certificate Information")) {
            anubis_parse_boolean(prefix, name, value, &config->certificate_information, NULL);
        }
        
        else {
            anubis_err("%s: \"Option\": \"%s\" unknown key\n", prefix, name);
        }//end else
    }//end for
    
}//end anubis_parse_socket_config

static void anubis_parse_socket_headers(char *prefix, anubis_t *config) {
    
    for(int i = 0 ; i < config->sequence_length ; i++) {
        if(config->sequence_data[i]->type != json_object) {
            anubis_err("%s: \"Sequence\" should be objects\n", prefix);
            return;
        }//end if
        
        json_value *json = config->sequence_data[i];
        
        for(int j = 0 ; j < json->u.object.length ; j++) {
            json_char *name = json->u.object.values[j].name;
            json_value *value = json->u.object.values[j].value;
            
            if(value->type != json_array) {
                anubis_err("%s: \"Send Packet\" or \"Receive Packet\" should be arrays\n", prefix);
                continue;
            }//end if
            
            if(!strcasecmp(name, "Send Packet")) {
                
                APPEND_PACKET(config);
                config->packets[config->packets_count-1].out_going = 1;
                for(int k = 0 ; k < value->u.array.length ; k++) {
                    
                    json_value *headers = value->u.array.values[k];
                    
                    if(headers->type != json_object) {
                        anubis_err("%s: Headers should be an object\n", prefix);
                        continue;
                    }//end if
                    
#pragma mark parse protocol
                    for(int x = 0 ; x < headers->u.object.length ; x++) {
                        json_char *protocol = headers->u.object.values[x].name;
                        json_value *header = headers->u.object.values[x].value;
                        
                        anubis_verbose("Socket[%d] Parsing: %s(Send)\n", config->index, protocol);
                        
                        if(!strcasecmp(protocol, "Ethernet")) {
                            struct libnet_ethernet_hdr ethernet_hdr = anubis_default_ethernet_header(config->device);
                            anubis_parse_ethernet_hdr(header, &ethernet_hdr, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_ethernet, ethernet_hdr);
                        }//end if ethernet
                        else if(!strcasecmp(protocol, "Wake-On-LAN")) {
                            anubis_wol_hdr wol_hdr = anubis_default_wol_header();
                            anubis_parse_wol_hdr(header, &wol_hdr, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_wol, wol_hdr);
                        }//end if wake-on-lan
                        else if(!strcasecmp(protocol, "ARP") || !strcasecmp(protocol, "RARP")) {
                            anubis_ether_arp_t arp_hdr = anubis_default_arp_header();
                            anubis_parse_arp_hdr(header, &arp_hdr, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_arp, arp_hdr);
                        }//end if arp
                        else if(!strcasecmp(protocol, "IP") || !strcasecmp(protocol, "IPv4")) {
                            struct libnet_ipv4_hdr ip_hdr = anubis_default_ip_header(config->device);
                            anubis_parse_ip_hdr(header, &ip_hdr, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_ip, ip_hdr);
                        }//end if ip
                        else if(!strcasecmp(protocol, "IP Options") || !strcasecmp(protocol, "IPv4 Options")) {
                            anubis_options_t ip_options = anubis_default_ip_options();
                            anubis_parse_ip_options(header, &ip_options, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_ip_option, ip_options);
                        }//end if ip options
                        else if(!strcasecmp(protocol, "UDP")) {
                            struct libnet_udp_hdr udp_hdr = anubis_default_udp_header();
                            anubis_parse_udp_hdr(header, &udp_hdr);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_udp, udp_hdr);
                        }//end if udp
                        else if(!strcasecmp(protocol, "TCP")) {
                            struct libnet_tcp_hdr tcp_hdr = anubis_default_tcp_header();
                            anubis_parse_tcp_hdr(header, &tcp_hdr);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_tcp, tcp_hdr);
                        }//end if udp
                        else if(!strcasecmp(protocol, "TCP Options") ) {
                            anubis_options_t tcp_options = anubis_default_tcp_options();
                            anubis_parse_tcp_options(header, &tcp_options, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_tcp_option, tcp_options);
                        }//end if tcp options
                        else if(!strcasecmp(protocol, "ICMP") || !strcasecmp(protocol, "ICMPv4")) {
                            anubis_icmp_t icmp_hdr = anubis_default_icmp_header();
                            anubis_parse_icmp_hdr(header, &icmp_hdr, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_icmp, icmp_hdr);
                        }//end if icmp echo
                        else if(!strcasecmp(protocol, "RIP")) {
                            anubis_packet_raw_data_t rip_hdr = anubis_default_rip_header();
                            anubis_parse_rip_hdr(header, &rip_hdr, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_rip, rip_hdr);
                        }//end if rip
                        else if(!strcasecmp(protocol, "SSDP")) {
                            anubis_message_hdr ssdp_hdr = anubis_default_ssdp_header();
                            anubis_parse_ssdp_hdr(header, &ssdp_hdr);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_ssdp, ssdp_hdr);
                        }//end if ssdp
                        else if(!strcasecmp(protocol, "HTTP")) {
                            anubis_message_hdr http_hdr = anubis_default_http_header();
                            anubis_parse_http_hdr(header, &http_hdr);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_http, http_hdr);
                        }//end if http
                        else if(!strcasecmp(protocol, "DHCP") || !strcasecmp(protocol, "DHCPv4")) {
                            struct libnet_dhcpv4_hdr dhcp_hdr = anubis_default_dhcp_header(config->device);
                            anubis_parse_dhcp_hdr(header, &dhcp_hdr, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_dhcp, dhcp_hdr);
                        }
                        else if(!strcasecmp(protocol, "DHCP Options") ) {
                            anubis_options_t dhcp_options = anubis_default_dhcp_options();
                            anubis_parse_dhcp_options(header, &dhcp_options, config->device);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_dhcp_option, dhcp_options);
                        }//end if dhcp options
                        else if(!strcasecmp(protocol, "Payload")) {
                            anubis_packet_raw_data_t payload = {0};
                            anubis_parse_payload(header, &payload);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_payload, payload);
                        }//end if payload
                        else if(!strcasecmp(protocol, "Raw Data")) {
                            anubis_packet_raw_data_t raw_data = {0};
                            anubis_parse_raw_data(header, &raw_data);
                            //append
                            APPEND_HEADER(config->packets[config->packets_count - 1], anubis_raw_data, raw_data);
                        }//end if payload
                        else if(!strcasecmp(protocol, "Packet Option")) {
                            anubis_parse_send_packet_option(header, config->socket_type, config->device,
                                                            &config->packets[config->packets_count - 1]);
                        }//end if option
                        else {
                            anubis_err("%s: \"%s\" unknown protocol\n", prefix, protocol);
                        }//end else
                    }//end for header field
                }//end for  headers
            }//end if send packet
            else if(config->socket_type == anubis_application_socket &&
                    !strcasecmp(name, "Receive Packet")) {
                APPEND_PACKET(config);
                config->packets[config->packets_count-1].out_going = 0;
                
                for(int k = 0 ; k < value->u.array.length ; k++) {
                    
                    json_value *headers = value->u.array.values[k];
                    
                    if(headers->type != json_object) {
                        anubis_err("%s: Headers should be an object\n", prefix);
                        continue;
                    }//end if
                    
                    for(int x = 0 ; x < headers->u.object.length ; x++) {
                        json_char *protocol = headers->u.object.values[x].name;
                        json_value *header = headers->u.object.values[x].value;
                        
                        anubis_verbose("Socket[%d] Parsing: %s(Receive)\n", config->index, protocol);
                        
                        if(!strcasecmp(protocol, "Packet Option")) {
                            anubis_parse_receive_packet_option(header, config->socket_type, config->device,
                                                               &config->packets[config->packets_count - 1]);
                        }//end if option
                        else {
                            anubis_err("%s: \"%s\" unknown key\n", prefix, protocol);
                        }//end else
                    }//end for
                }//end for
            }//end if receive
            else {
                anubis_err("%s: \"%s\" unknown key\n", prefix, name);
            }//end else
        }//end for Packet array
    }//end for Sequence object
}//end anubis_parse_socket_headers

#pragma mark others
void anubis_parse_socket_type(json_value *json, int index, anubis_model_callback_t *callback) {
    if(json->type != json_object) {
        anubis_err("Each sub-socket should be an object\n");
        return;
    }//end if
    
    //figure out socket type
    char *socket_type = NULL;
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Socket-type")) {
            anubis_parse_string("Data-link", name, value, &socket_type, NULL);
        }//end if
    }//end for
    
    //check
    if(!socket_type) {
        anubis_err("\"Socket-type\" is empty\n");
        return;
    }//end if
    
    if(strlen(socket_type) <= 0) {
        anubis_err("\"Socket-type\" is not configured\n");
        return;
    }//end if
    
    //fill config
    anubis_t config = {0};
    
    memset(&config, 0, sizeof(config));
    config.index = index;
    config.callback = callback;
    
    if(!strcasecmp(socket_type, "Data-link")) {
        config.socket_type = anubis_data_link_socket;
        anubis_verbose("Socket[%d] Start parsing data-link socket configuration\n", config.index);
        anubis_parse_socket_config(json, &config);
        anubis_verbose("Socket[%d] Check requirement of data-link configuration\n", config.index);
        if(anubis_check_config_requirement(&config)) {
            anubis_free_config(&config);
            return;
        }//end if
        anubis_verbose("Socket[%d] Start parsing headers\n", config.index);
        anubis_parse_socket_headers("Data-link", &config);
        anubis_verbose("Socket[%d] Start injection\n", config.index);
        anubis_write_data_link_or_network(&config);
        anubis_verbose("Socket[%d] Injection done\n", config.index);
    }//end if data-link
    else if(!strcasecmp(socket_type, "Network")) {
        config.socket_type = anubis_network_socket;
        anubis_verbose("Socket[%d] Start parsing network socket configuration\n", config.index);
        anubis_parse_socket_config(json, &config);
        anubis_verbose("Socket[%d] Check requirement of network configuration\n", config.index);
        if(anubis_check_config_requirement(&config)) {
            anubis_free_config(&config);
            return;
        }//end if
        anubis_verbose("Socket[%d] Start parsing headers\n", config.index);
        anubis_parse_socket_headers("Network", &config);
        anubis_verbose("Socket[%d] Start injection\n", config.index);
        anubis_write_data_link_or_network(&config);
        anubis_verbose("Socket[%d] Injection done\n", config.index);
    }//end if network
    else if(!strcasecmp(socket_type, "Transport")) {
        config.socket_type = anubis_transport_socket;
        anubis_verbose("Socket[%d] Start parsing transport socket configuration\n", config.index);
        anubis_parse_socket_config(json, &config);
        anubis_verbose("Socket[%d] Check requirement of network configuration\n", config.index);
        if(anubis_check_config_requirement(&config)) {
            anubis_free_config(&config);
            return;
        }//end if
        anubis_verbose("Socket[%d] Start parsing headers\n", config.index);
        anubis_parse_socket_headers("Transport", &config);
        anubis_verbose("Socket[%d] Start injection\n", config.index);
        anubis_write_transport(&config);
        anubis_verbose("Socket[%d] Injection done\n", config.index);
    }//end if transport
    else if(!strcasecmp(socket_type, "Application")) {
        config.socket_type = anubis_application_socket;
        anubis_verbose("Socket[%d] Start parsing application socket configuration\n", config.index);
        anubis_parse_socket_config(json, &config);
        anubis_verbose("Socket[%d] Check requirement of application configuration\n", config.index);
        if(anubis_check_config_requirement(&config)) {
            anubis_free_config(&config);
            return;
        }//end if
        anubis_verbose("Socket[%d] Start parsing headers\n", config.index);
        anubis_parse_socket_headers("Application", &config);
        anubis_verbose("Socket[%d] Start injection\n", config.index);
        anubis_write_application(&config);
        anubis_verbose("Socket[%d] Injection done\n", config.index);
    }//end if application
    else {
        anubis_err("Socket: \"%s\" unknown socket type\n", socket_type);
        return;
    }//end else
    
    anubis_free_config(&config);
}//end anubis_parse_socket_type

void anubis_free_config(anubis_t *config) {
    //free
    for(int i = 0 ; i < config->packets_count ; i++) {
        anubis_packet_t *packet = config->packets;
        if(!packet || !packet->protocols)
            continue;
        
        if(packet->output_filename)
            free(packet->output_filename);
        packet->output_filename = NULL;
        
        if(packet->input_filename)
            free(packet->input_filename);
        packet->input_filename = NULL;
        
        //free specific protocol
        for(int j = 0 ; j < packet->layers ; j++) {
            anubis_protocol_t protocol = packet->protocols[j];
            
            //free options if need
            if(protocol.protocol_type == anubis_ip_option &&
               protocol.u.ip_options.options) {
                free(protocol.u.ip_options.options);
            }
            else if(protocol.protocol_type == anubis_tcp_option &&
                    protocol.u.tcp_options.options) {
                free(protocol.u.tcp_options.options);
            }
            else if(protocol.protocol_type == anubis_dhcp_option &&
                    protocol.u.dhcp_options.options) {
                free(protocol.u.dhcp_options.options);
            }
            else if(protocol.protocol_type == anubis_rip &&
                    protocol.u.rip.data) {
                free(protocol.u.rip.data);
            }
            
            //free message
            else if(protocol.protocol_type == anubis_ssdp ||
                    protocol.protocol_type == anubis_http) {
                anubis_message_hdr *meesage_hdr = NULL;
                
                if(protocol.protocol_type == anubis_ssdp)
                    meesage_hdr = &protocol.u.ssdp;
                else if(protocol.protocol_type == anubis_http)
                    meesage_hdr = &protocol.u.http;
                else
                    continue;
                
                if(meesage_hdr->status_line)
                    free(meesage_hdr->status_line);
                if(meesage_hdr->keys)
                    free(meesage_hdr->keys);
                if(meesage_hdr->values)
                    free(meesage_hdr->values);
                if(meesage_hdr->fields)
                    free(meesage_hdr->fields);
                if(meesage_hdr->data)
                    free(meesage_hdr->data);
            }//end if ssdp or http
            
        }//end if
        
        //free packet
        if(config->packets[i].protocols)
            free(config->packets[i].protocols);
        config->packets[i].protocols = NULL;
    }//end for
    if(config->packets)
        free(config->packets);
    if(config->device)
        free(config->device);
    if(config->comment)
        free(config->comment);
    if(config->muliticast_groups)
        free(config->muliticast_groups);
    if(config->sslMethod)
        free(config->sslMethod);
    if(config->certificate_file)
        free(config->certificate_file);
    if(config->private_key_file)
        free(config->private_key_file);
    
    config->packets = NULL;
    config->device = NULL;
    config->comment = NULL;
    config->muliticast_groups = NULL;
    config->sslMethod = NULL;
    config->certificate_file = NULL;
    config->private_key_file = NULL;
}//end anubis_free_config

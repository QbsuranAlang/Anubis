//
//  anubis_model_arpoison.c
//  Anubis
//
//  Created by TUTU on 2016/6/26.
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

void anubis_default_model_arpoison(anubis_model_t *model) {
    model->infinite_loop = 1;
    model->interval = 3000000; //3s
    char *tmp = anubis_default_device();
    if(tmp)
        model->device = strdup(tmp);
    if(!model->device)
        anubis_perror("strdup()");
}//end anubis_default_model_arpoison

static void anubis_free_model_arpoison(anubis_model_arpoison_t *arpoison_model);
static void anubis_run_model_arpoison(anubis_model_arpoison_t *arpoison_model);

void anubis_parse_model_arpoison(json_value *json, anubis_model_t *model) {
    anubis_model_arpoison_t arpoison_model = {0};
    
    memset(&arpoison_model, 0, sizeof(arpoison_model));
    memmove(&arpoison_model.model, model, sizeof(arpoison_model.model));
    
    //check requrement first
    CHECK_REQUIREMENT(arpoison_model.model.device, "Model", "Device");
    if(!arpoison_model.model.device) {
        return;
    }//end if
    
    //set default value
    arpoison_model.ar_pro = ARPOP_REPLY;
    arpoison_model.interval = 10000;
    arpoison_model.arp_sha = "myself";
    
    //parse arping model fields
    int required_hosts = 0;
    int required_reversed = 0;
    int required_op = 0;
    
    for(int i = 0 ; i < json->u.object.length ; i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Hosts")) {
            anubis_parse_host_list("arpoison", name, value,
                                   &arpoison_model.host_list, &arpoison_model.host_list_length,
                                   arpoison_model.model.device, &required_hosts);
        }//end if
        else if(!strcasecmp(name, "Reversed")) {
            anubis_parse_ip_address("arpoison", name, value,
                                    &arpoison_model.reversed_ip_address, sizeof(arpoison_model.reversed_ip_address),
                                    arpoison_model.model.device, &required_reversed);
        }//end if
        else if(!strcasecmp(name, "Interval")) {
            anubis_parse_4bytes_integer("arpoison", name, value, &arpoison_model.interval, NULL);
        }//end if
        else if(!strcasecmp(name, "White")) {
            anubis_parse_host_list("arpoison", name, value,
                                   &arpoison_model.white_list, &arpoison_model.white_list_length,
                                   arpoison_model.model.device, NULL);
        }//end if
        else if(!strcasecmp(name, "Sender Hardware Address")) {
            //try parameter ok or not
            int sha = 0;
            u_int8_t temp[ETH_ADDR_LEN];
            anubis_parse_mac_address("arpoison", name, value,
                                     temp, sizeof(temp),
                                     arpoison_model.model.device, &sha);
            arpoison_model.arp_sha = "";
            if(sha) {
                sha = 0;
                anubis_parse_string("arpoison", name, value, &arpoison_model.arp_sha, &sha);
            }//end if ok, get parameter
        }//end if
        else if(!strcasecmp(name, "Operation")) {
            CHECK_INTEGER_OR_STRING_TYPE(value, "arpoison");
            
            if(value->type == json_integer) {
                anubis_parse_2bytes_integer("arpoison", name, value, &arpoison_model.ar_pro, &required_op);
                continue;
            }//end if
            
            COMPARE_DEFINE(value->u.string.ptr, ARPOP_REPLY, arpoison_model.ar_pro, required_op)
            else
                COMPARE_DEFINE(value->u.string.ptr, ARPOP_REQUEST, arpoison_model.ar_pro, required_op)
            else
                anubis_parse_2bytes_integer("arpoison", name, value, &arpoison_model.ar_pro, &required_op);
        }//end if
        else {
            anubis_err("arpoison: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    //check requirement
    CHECK_REQUIREMENT(required_hosts, "arpoison", "Hosts");
    CHECK_REQUIREMENT(required_reversed, "arpoison", "Reversed");
    CHECK_REQUIREMENT(required_op, "arpoison", "Operation");
    if(!required_hosts || !required_reversed || !required_op) {
        goto BYE;
    }//end if
    
    //run
    anubis_run_model_arpoison(&arpoison_model);
    
    //free
BYE:
    anubis_free_model_arpoison(&arpoison_model);
}//end anubis_parse_model_arpoison

static void anubis_free_model_arpoison(anubis_model_arpoison_t *arpoison_model) {
    if(arpoison_model->host_list)
        free(arpoison_model->host_list);
    
    arpoison_model->host_list = NULL;
}//end anubis_free_model_arpoison

static int anubis_model_arpoison_callback(const u_char *data, struct timeval *send_time) {
    anubis_model_arpoison_t *arpison_model = (anubis_model_arpoison_t *)data;
    
    if(arpison_model->swap) {
        arpison_model->swap = 0;
        anubis_out("Round: %llu, sent via \"%s\", %s: %llu, \"%s\" and \"%s\"\n",
                   arpison_model->round + 1,
                   arpison_model->model.device,
                   arpison_model->ar_pro == ARPOP_REPLY ? "Reply" :
                   arpison_model->ar_pro == ARPOP_REQUEST ? "Request": "Unknown",
                   ++arpison_model->index,
                   anubis_ip_ntoa(arpison_model->current_ip_address),
                   anubis_ip_ntoa(arpison_model->reversed_ip_address));
    }//end if
    else {
        arpison_model->swap = 1;
        anubis_out("Round: %llu, sent via \"%s\", %s: %llu, \"%s\" and \"%s\"\n",
                   arpison_model->round + 1,
                   arpison_model->model.device,
                   arpison_model->ar_pro == ARPOP_REPLY ? "Reply" :
                   arpison_model->ar_pro == ARPOP_REQUEST ? "Request": "Unknown",
                   ++arpison_model->index,
                   anubis_ip_ntoa(arpison_model->reversed_ip_address),
                   anubis_ip_ntoa(arpison_model->current_ip_address));
    }//end else
    
    
    return 0;
}//end anubis_model_arpoison_callback

static void anubis_run_model_arpoison(anubis_model_arpoison_t *arpoison_model) {
    
    u_int64_t outter_amount = 0;
    
    //whole config file injection
    if(arpoison_model->model.infinite_loop)
        outter_amount = -1;
    else if(arpoison_model->model.amount)
        outter_amount = arpoison_model->model.amount;
    else
        outter_amount = 1;
    
    while(outter_amount--) {
        if(arpoison_model->model.infinite_loop)
            outter_amount = -1;
        
        for(int i = 0; i < arpoison_model->host_list_length ;) {
            in_addr_t start_ip = arpoison_model->host_list[i++];
            in_addr_t end_ip = arpoison_model->host_list[i++];
            for(in_addr_t j = ntohl(start_ip) ; j <= ntohl(end_ip) ; j++) {
                in_addr_t current_ip = htonl(j);
                arpoison_model->current_ip_address = current_ip;
                
                //for white list
                for(int k = 0 ; k < arpoison_model->white_list_length ;) {
                    in_addr_t white_start_ip = arpoison_model->white_list[k++];
                    in_addr_t white_end_ip = arpoison_model->white_list[k++];
                    for(int m = ntohl(white_start_ip) ; m <= ntohl(white_end_ip) ; m++) {
                        in_addr_t white_current_ip = htonl(m);
                        
                        if(current_ip == white_current_ip) {
                            anubis_out("arpoison: Current IP address: \"%s\" in white list\n", anubis_ip_ntoa(current_ip));
                            goto NEXT_LOOP;
                        }//end if
                    }
                }//end for white
                
                char temp_json[65535] = {0};
                char comment_buffer[65535] = {0};
                
                snprintf(comment_buffer, sizeof(comment_buffer), "\t\t\"_comment\": \"%s\",\n",
                         arpoison_model->model.comment ? arpoison_model->model.comment : "");
                
                if(arpoison_model->ar_pro == ARPOP_REPLY) {
                    snprintf(temp_json, sizeof(temp_json),
                             "\n[\n"
                             "\t{\n"
                             "%s"
                             "\t\t\"Socket-type\": \"Data-link\",\n"
                             "\t\t\"Option\": {\n"
                             "\t\t\t\"Device\": \"%s\"\n"
                             "\t\t},\n"
                             "\t\t\"Sequence\": [\n"
                             "\t\t\t{\n"
                             "\t\t\t/*Send frame of target 1*/\n"
                             "\t\t\t\t\"Send Packet\": [\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"Ethernet\": {\n"
                             "\t\t\t\t\t\t\t\"Destination MAC Address\": \"lookup_mac_address(%s)\",\n"
                             "\t\t\t\t\t\t\t\"Source MAC Address\": \"myself\",\n"
                             "\t\t\t\t\t\t\t\"Type\": \"ETHERTYPE_ARP\"\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t},\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"ARP\": {\n"
                             "\t\t\t\t\t\t\t\"Operation\": %d, \n"
                             "\t\t\t\t\t\t\t\"Sender Hardware Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Sender Protocol Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Target Hardware Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Target Protocol Address\": \"%s\"\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t},\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"Packet Option\": {\n"
                             "\t\t\t\t\t\t\t\"Interval\": %d,\n"
                             "\t\t\t\t\t\t\t\"Dump send packet\": %d\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t}\n"
                             "\t\t\t\t]\n"
                             "\t\t\t},\n"
                             "\t\t\t/*Send frame of target 2*/\n"
                             "\t\t\t{\n"
                             "\t\t\t\t\"Send Packet\": [\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"Ethernet\": {\n"
                             "\t\t\t\t\t\t\t\"Destination MAC Address\": \"lookup_mac_address(%s)\",\n"
                             "\t\t\t\t\t\t\t\"Source MAC Address\": \"myself\",\n"
                             "\t\t\t\t\t\t\t\"Type\": \"ETHERTYPE_ARP\"\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t},\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"ARP\": {\n"
                             "\t\t\t\t\t\t\t\"Operation\": %d,\n"
                             "\t\t\t\t\t\t\t\"Sender Hardware Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Sender Protocol Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Target Hardware Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Target Protocol Address\": \"%s\"\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t},\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"Packet Option\": {\n"
                             "\t\t\t\t\t\t\t\"Interval\": %d,\n"
                             "\t\t\t\t\t\t\t\"Dump send packet\": %d\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t}\n"
                             "\t\t\t\t]\n"
                             "\t\t\t}\n"
                             "\t\t]\n"
                             "\t}\n"
                             "]",
                             arpoison_model->model.comment ? comment_buffer : "",
                             arpoison_model->model.device,
                             anubis_ip_ntoa(arpoison_model->reversed_ip_address),
                             arpoison_model->ar_pro,
                             arpoison_model->arp_sha,
                             anubis_ip_ntoa(current_ip),
                             anubis_ip_ntoa(arpoison_model->reversed_ip_address),
                             anubis_ip_ntoa(arpoison_model->reversed_ip_address),
                             arpoison_model->interval,
                             arpoison_model->model.dump_send,
                             anubis_ip_ntoa(current_ip),
                             arpoison_model->ar_pro,
                             arpoison_model->arp_sha,
                             anubis_ip_ntoa(arpoison_model->reversed_ip_address),
                             anubis_ip_ntoa(current_ip),
                             anubis_ip_ntoa(current_ip),
                             arpoison_model->interval,
                             arpoison_model->model.dump_send);
                }//end if
                else if(arpoison_model->ar_pro == ARPOP_REQUEST) {
                    snprintf(temp_json, sizeof(temp_json),
                             "\n[\n"
                             "\t{\n"
                             "%s"
                             "\t\t\"Socket-type\": \"Data-link\",\n"
                             "\t\t\"Option\": {\n"
                             "\t\t\t\"Device\": \"%s\"\n"
                             "\t\t},\n"
                             "\t\t\"Sequence\": [\n"
                             "\t\t\t{\n"
                             "\t\t\t/*Send frame of target 1*/\n"
                             "\t\t\t\t\"Send Packet\": [\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"Ethernet\": {\n"
                             "\t\t\t\t\t\t\t\"Destination MAC Address\": \"Broadcast\",\n"
                             "\t\t\t\t\t\t\t\"Source MAC Address\": \"myself\",\n"
                             "\t\t\t\t\t\t\t\"Type\": \"ETHERTYPE_ARP\"\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t},\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"ARP\": {\n"
                             "\t\t\t\t\t\t\t\"Operation\": %d, \n"
                             "\t\t\t\t\t\t\t\"Sender Hardware Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Sender Protocol Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Target Hardware Address\": \"00:00:00:00:00:00\",\n"
                             "\t\t\t\t\t\t\t\"Target Protocol Address\": \"%s\"\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t},\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"Packet Option\": {\n"
                             "\t\t\t\t\t\t\t\"Interval\": %d,\n"
                             "\t\t\t\t\t\t\t\"Dump send packet\": %d\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t}\n"
                             "\t\t\t\t]\n"
                             "\t\t\t},\n"
                             "\t\t\t/*Send frame of target 2*/\n"
                             "\t\t\t{\n"
                             "\t\t\t\t\"Send Packet\": [\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"Ethernet\": {\n"
                             "\t\t\t\t\t\t\t\"Destination MAC Address\": \"Broadcast\",\n"
                             "\t\t\t\t\t\t\t\"Source MAC Address\": \"myself\",\n"
                             "\t\t\t\t\t\t\t\"Type\": \"ETHERTYPE_ARP\"\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t},\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"ARP\": {\n"
                             "\t\t\t\t\t\t\t\"Operation\": %d,\n"
                             "\t\t\t\t\t\t\t\"Sender Hardware Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Sender Protocol Address\": \"%s\",\n"
                             "\t\t\t\t\t\t\t\"Target Hardware Address\": \"00:00:00:00:00:00\",\n"
                             "\t\t\t\t\t\t\t\"Target Protocol Address\": \"%s\"\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t},\n"
                             "\t\t\t\t\t{\n"
                             "\t\t\t\t\t\t\"Packet Option\": {\n"
                             "\t\t\t\t\t\t\t\"Interval\": %d,\n"
                             "\t\t\t\t\t\t\t\"Dump send packet\": %d\n"
                             "\t\t\t\t\t\t}\n"
                             "\t\t\t\t\t}\n"
                             "\t\t\t\t]\n"
                             "\t\t\t}\n"
                             "\t\t]\n"
                             "\t}\n"
                             "]",
                             arpoison_model->model.comment ? comment_buffer : "",
                             arpoison_model->model.device,
                             arpoison_model->ar_pro,
                             arpoison_model->arp_sha,
                             anubis_ip_ntoa(current_ip),
                             anubis_ip_ntoa(arpoison_model->reversed_ip_address),
                             arpoison_model->interval,
                             arpoison_model->model.dump_send,
                             arpoison_model->ar_pro,
                             arpoison_model->arp_sha,
                             anubis_ip_ntoa(arpoison_model->reversed_ip_address),
                             anubis_ip_ntoa(current_ip),
                             arpoison_model->interval,
                             arpoison_model->model.dump_send);
                }//end if
                
                if(arpoison_model->model.save_config) {
                    anubis_save_to_file(arpoison_model->model.save_config, temp_json);
                }//end if
                
                anubis_model_callback_t callback = {0};
                callback.callback = anubis_model_arpoison_callback;
                callback.data = (const u_char *)arpoison_model;

                anubis_parse_json_string(temp_json, strlen(temp_json) + 1, &callback);
                
            NEXT_LOOP:
                continue;
            }//end for
        }//end for
        
        if(arpoison_model->model.interval) {
            anubis_wait_microsecond(arpoison_model->model.interval);
        }//end if
        arpoison_model->round++;
    }//end while
    
    
}//end anubis_run_model_arpoison
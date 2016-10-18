//
//  anubis_model_arping.c
//  Anubis
//
//  Created by TUTU on 2016/6/25.
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

void anubis_default_model_arping(anubis_model_t *model) {
    model->amount = 1;
    model->recv_timeout = 1;
    char *tmp = anubis_default_device();
    if(tmp)
        model->device = strdup(tmp);
    if(!model->device)
        anubis_perror("strdup()");
}//end anubis_default_model_arping

static void anubis_free_model_arping(anubis_model_arping_t *arping_model);
static void anubis_run_model_arping(anubis_model_arping_t *arping_model);

void anubis_parse_model_arping(json_value *json, anubis_model_t *model) {
    
    anubis_model_arping_t arping_model = {0};
    int tpa = 0;
    
    //copy base structure
    memset(&arping_model, 0, sizeof(arping_model));
    memmove(&arping_model.model, model, sizeof(arping_model.model));
    
    //check requrement first
    CHECK_REQUIREMENT(arping_model.model.device, "Model", "Device");
    if(!arping_model.model.device) {
        return;
    }//end if
    
    //parse arping model fields
    for(int i = 0 ; i < json->u.object.length ; i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Target")) {
            anubis_parse_ip_address("arping", name, value,
                                    &arping_model.arp_target, sizeof(arping_model.arp_target),
                                    arping_model.model.device, &tpa);
        }//end if
        else {
            anubis_err("arping: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    //check requirement
    CHECK_REQUIREMENT(tpa, "arping", "Target");
    if(!tpa) {
        goto BYE;
    }//end if
    
    //set default filter
    if(!model->filter) {
        char buffer[65535] = {0};
        snprintf(buffer, sizeof(buffer), "arp host %s and arp[6:2] == 0x0002", anubis_ip_ntoa(arping_model.arp_target));
        anubis_verbose("Default filter: \"%s\"\n", buffer);
        model->filter = strdup(buffer);
        if(!model->filter) {
            anubis_perror("strdup()");
            goto BYE;
        }//end if
    }//end if
    
    //copy base model
    memmove(&arping_model.model, model, sizeof(arping_model.model));
    
    //open pcap handle
    pcap_t *pcap_handle = anubis_open_pcap(arping_model.model.device,
                                           arping_model.model.recv_timeout,
                                           arping_model.model.filter);
    if(!pcap_handle) {
        goto BYE;
    }//end if
    
    //set pcap handle
    arping_model.model.pcap_handle = pcap_handle;
    
    //run
    anubis_run_model_arping(&arping_model);
    
    //free
BYE:
    anubis_free_model_arping(&arping_model);
}//end anubis_parse_model_arping

static void anubis_arping_callback(u_char *data, const struct pcap_pkthdr *header, const u_char *content) {
    const anubis_model_arping_t *arping_model = (const anubis_model_arping_t *)data;
    u_int32_t dump_length = 0;
    u_int32_t spa;
    anubis_ether_arp_t *arp;
    
    struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr *)content;
    
    if(ntohs(ethernet->ether_type) != ETHERTYPE_ARP)
        return;
    
    arp = (anubis_ether_arp_t *)(content + LIBNET_ETH_H);
    memmove(&spa, arp->arp_spa, sizeof(spa));
    
    //if found
    if(spa == arping_model->arp_target) {
        long microseconds = anubis_subtract_time(*(arping_model->model.send_time), header->ts);
        double milliseconds = microseconds / 1000.;
        anubis_out("arping: Received from \"%s\" at \"%s\", time: %.3f milliseconds\n",
                   anubis_ip_ntoa(spa), anubis_mac_ntoa(arp->arp_sha), milliseconds);
        
        if(arping_model->model.dump_recv) {
            anubis_dump_ethernet(&dump_length, header->caplen, content);
        }//end if
    }//end if found
}//end anubis_arping_callback

static int anubis_model_arping_callback(const u_char *data, struct timeval *send_time) {
    
    anubis_model_arping_t *arping_model = (anubis_model_arping_t *)data;
    pcap_t *pcap_handle = arping_model->model.pcap_handle;
    arping_model->model.send_time = send_time;
    
    int ret = pcap_dispatch(pcap_handle, -1, anubis_arping_callback, (u_char *)data);
    
    if(-1 == ret) {
        anubis_err("pcap_dispatch(): %s\n", pcap_geterr(pcap_handle));
    }//end if
    else if(0 == ret) {
        anubis_out("Timeout\n");
    }//end else
    
    return 0;
}//end anubis_model_arping_callback

static void anubis_run_model_arping(anubis_model_arping_t *arping_model) {
    
    anubis_out("arping: arping to \"%s\"\n", anubis_ip_ntoa(arping_model->arp_target));
    
    char temp_json[65535] = {0};
    char comment_buffer[65535] = {0};
    
    snprintf(comment_buffer, sizeof(comment_buffer), "\t\t\"_comment\": \"%s\",\n",
             arping_model->model.comment ? arping_model->model.comment : "");
    
    snprintf(temp_json, sizeof(temp_json),
             "\n[\n"
             "\t{\n"
             "\t\t\"Socket-type\": \"Data-link\",\n"
             "%s"
             "\t\t\"Option\": {\n"
             "\t\t\t\"Device\": \"%s\",\n"
             "\t\t\t\"Amount\": %d,\n"
             "\t\t\t\"Interval\": %d,\n"
             "\t\t\t\"Infinite loop\": %d\n"
             "\t\t},\n"
             "\t\t\"Sequence\": [\n"
             "\t\t\t{\n"
             "\t\t\t\t\"Send Packet\": [\n"
             "\t\t\t\t\t{\n"
             "\t\t\t\t\t\t\"Ethernet\": {\n"
             "\t\t\t\t\t\t\t\"Destination MAC Address\": \"Broadcast\",\n"
             "\t\t\t\t\t\t\t\"Source MAC Address\": \"Myself\",\n"
             "\t\t\t\t\t\t\t\"Type\": \"ETHERTYPE_ARP\"\n"
             "\t\t\t\t\t\t}\n"
             "\t\t\t\t\t},\n"
             "\t\t\t\t\t{\n"
             "\t\t\t\t\t\t\"ARP\": {\n"
             "\t\t\t\t\t\t\t\"Operation\": \"ARPOP_REQUEST\",\n"
             "\t\t\t\t\t\t\t\"Sender Hardware Address\": \"Myself\",\n"
             "\t\t\t\t\t\t\t\"Sender Protocol Address\": \"Myself\",\n"
             "\t\t\t\t\t\t\t\"Target Hardware Address\": \"00:00:00:00:00:00\",\n"
             "\t\t\t\t\t\t\t\"Target Protocol Address\": \"%s\"\n"
             "\t\t\t\t\t\t}\n"
             "\t\t\t\t\t},\n"
             "\t\t\t\t\t{\n"
             "\t\t\t\t\t\t\"Packet Option\": {\n"
             "\t\t\t\t\t\t\t\"Dump send packet\": %d\n"
             "\t\t\t\t\t\t}\n"
             "\t\t\t\t\t}\n"
             "\t\t\t\t]\n"
             "\t\t\t}\n"
             "\t\t]\n"
             "\t}\n"
             "]",
             arping_model->model.comment ? comment_buffer : "",
             arping_model->model.device,
             arping_model->model.amount,
             arping_model->model.interval,
             arping_model->model.infinite_loop,
             anubis_ip_ntoa(arping_model->arp_target),
             arping_model->model.dump_recv);
    
    //anubis_verbose("arping JSON configuration: %s\n", temp_json);
    
    if(arping_model->model.save_config) {
        anubis_save_to_file(arping_model->model.save_config, temp_json);
    }//end if
    anubis_model_callback_t callback = {0};
    callback.callback = anubis_model_arping_callback;
    callback.data = (const u_char *)arping_model;
    
    anubis_parse_json_string(temp_json, strlen(temp_json) + 1, &callback);
    
}//end anubis_run_model_arping

static void anubis_free_model_arping(anubis_model_arping_t *arping_model) {
    //nothing to do
}//end anubis_free_model_arping

void anubis_arping(const char *device, const char *ip_address) {
    char temp_json[65535] = {0};
    
    snprintf(temp_json, sizeof(temp_json),
             "{\n"
             "\t\"Option\": {\n"
             "\t\t\"Model\": \"arping\",\n"
             "\t\t\"Device\": \"%s\",\n"
             "\t\t\"Receive Timeout\": 1\n"
             "\t},\n"
             "\t\"Model\": {\n"
             "\t\t\"Target\": \"%s\",\n"
             "\t}\n"
             "}"
             , device, ip_address);
    anubis_parse_json_string(temp_json, strlen(temp_json), NULL);
}//end anubis_arping

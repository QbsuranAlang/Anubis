//
//  anubis_write_transport.c
//  Anubis
//
//  Created by TUTU on 2016/6/25.
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

void anubis_write_transport(anubis_t *config) {
    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    u_int64_t inner_amount = 0;
    u_int64_t outter_amount = 0;
    libnet_t *libnet_handle = NULL;
    struct sockaddr_in sin = {0};
    int sd;
    
#ifdef __CYGWIN__
    char device2[ANUBIS_BUFFER_SIZE] = {0};
    snprintf(device2, sizeof(device2), "\\Device\\NPF_%s", config->device);
    libnet_handle = anubis_libnet_init(LIBNET_RAW4, device2, errbuf);
#else
    libnet_handle = anubis_libnet_init(LIBNET_RAW4, config->device, errbuf);
#endif
    
    if(!libnet_handle) {
        anubis_err("%s\n", errbuf);
        return;
    }//end if
    
    if(config->comment)
        anubis_verbose("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
    
    //dst
    memset(&sin, 0, sizeof(sin));
    sin.sin_family  = AF_INET;
    sin.sin_addr.s_addr = config->dst_ip;
    
    //open socket
    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        anubis_perror("socket()");
        return;
    }//end if
    
    //set socket option
    sd = anubis_set_socket_option(config, sd);
    if(sd == -1)
        return;
    
    //whole config file injection
    if(config->infinite_loop)
        outter_amount = -1;
    else if(config->amount)
        outter_amount = config->amount;
    else
        outter_amount = 1;
    
    while(outter_amount--) {
        if(config->infinite_loop)
            outter_amount = -1;
        
        //peer packet injection
        for(int i = 0 ; i < config->packets_count ; i++) {
            libnet_clear_packet(libnet_handle);
            anubis_packet_t *packet = &config->packets[i];
            anubis_build_headers(libnet_handle, packet);
            
            if(libnet_handle->total_size == 0 || packet->layers == 0) {
                anubis_err("Socket[%d] Empty packet\n", config->index);
                continue;
            }//end if
            
            //build fake header
            if(anubis_build_fake_header(config, libnet_handle, config->protocol, 0, 1) == -1) {
                continue;
            }//end if
            
            int c;
            uint32_t content_length = 0;
            uint8_t *content = NULL;
            c = libnet_pblock_coalesce(libnet_handle, &content, &content_length);
            if (c == -1) {
                anubis_err("libnet_pblock_coalesce(): %s\n", libnet_geterror(libnet_handle));
                continue;
            }//end if
            
            //inject amount
            if(packet->infinite_loop)
                inner_amount = -1;
            else if(packet->amount)
                inner_amount = packet->amount;
            else
                inner_amount = 1;
            
            while(inner_amount--) {
                if(packet->infinite_loop)
                    inner_amount = -1;
                
                if(config->protocol == IPPROTO_TCP)
                    anubis_verbose("Sending segment\n");
                else if(config->protocol == IPPROTO_UDP)
                    anubis_verbose("Sending user datagram\n");
                else
                    anubis_verbose("Sending datagram\n");
                
                int ret = (int)sendto(sd, content + LIBNET_IPV4_H, content_length - LIBNET_IPV4_H,
                                      0,
                                      (struct sockaddr *)&sin, sizeof(sin));
                
                if(ret < 0) {
                    anubis_perror("sendto()");
                }//end if
                else {
                    anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                    if(packet->dump_send)
                        anubis_dump_libnet_content(libnet_handle, 1, 0);
                }//end else
                
                if(packet->interval) {
                    anubis_wait_microsecond(packet->interval);
                }//end if
            }//end while inner inject
            
#ifndef __CYGWIN__
            //free
            if (libnet_handle->aligner > 0) {
                content = content - libnet_handle->aligner;
            }//end if
            free(content);
#endif
            content = NULL;
        }//end for
        
        if(config->interval) {
            anubis_wait_microsecond(config->interval);
        }//end if
        
    }//end while outter inject
    
    //free
    close(sd);
    libnet_destroy(libnet_handle);
}//end anubis_write_transport

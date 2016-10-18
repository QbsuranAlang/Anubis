//
//  anubis_write_data_link_or_network.c
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

void anubis_write_data_link_or_network(anubis_t *config) {
    
    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    u_int64_t inner_amount = 0;
    u_int64_t outter_amount = 0;
    libnet_t *libnet_handle = NULL;
    
    int libnet_type = config->socket_type == anubis_data_link_socket ? LIBNET_LINK :
    config->socket_type == anubis_network_socket ? LIBNET_RAW4 :
    config->socket_type == anubis_transport_socket ? LIBNET_RAW4 : -1;
    
    if(libnet_type == -1) {
        anubis_err("anubis_write_data_link_or_network(): invalid socket type: %d\n", config->socket_type);
        return;
    }//end if
    
#ifdef __CYGWIN__
    char device2[ANUBIS_BUFFER_SIZE] = {0};
    snprintf(device2, sizeof(device2), "\\Device\\NPF_%s", config->device);
    libnet_handle = anubis_libnet_init(libnet_type, device2, errbuf);
#else
    libnet_handle = anubis_libnet_init(libnet_type, config->device, errbuf);
#endif
    
    if(!libnet_handle) {
        anubis_err("%s\n", errbuf);
        return;
    }//end if
    
    if(config->comment)
        anubis_verbose("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
    
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
            
            if(libnet_handle->total_size == 0) {
                anubis_err("Socket[%d] Empty packet\n", config->index);
                continue;
            }//end if
            
            if(packet->infinite_loop)
                inner_amount = -1;
            else if(packet->amount)
                inner_amount = packet->amount;
            else
                inner_amount = 1;
            
            while(inner_amount--) {
                if(packet->infinite_loop)
                    inner_amount = -1;
                
                if(config->socket_type == anubis_data_link_socket)
                    anubis_verbose("Sending frame\n");
                else if(config->socket_type == anubis_network_socket)
                    anubis_verbose("Sending packet\n");
                    
                int ret = libnet_write(libnet_handle);
                
                //get now time
                struct timeval send_time;
                if(config->callback && config->callback->callback) {
                    gettimeofday(&send_time, 0);
                }//end if
                
                if(ret <= 0) {
                    anubis_err("libnet_write(): %s\n", libnet_geterror(libnet_handle));
                }//end if
                else {
                    
                    anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                    if(packet->dump_send)
                        anubis_dump_libnet_content(libnet_handle, 0, 0);
                    
                    if(config->callback && config->callback->callback) {
                        int ret = config->callback->callback(config->callback->data, &send_time);
                        if(ret != 0) {
                            anubis_verbose("Froce to exit\n");
                            goto BYE;
                        }
                    }//end if
                    
                }//end else
                
                if(packet->interval) {
                    anubis_wait_microsecond(packet->interval);
                }//end if
            }//end while inner inject
            
        }//end for
        
        if(config->interval) {
            anubis_wait_microsecond(config->interval);
        }//end if
    }//end while outter inject
    
BYE:
    //free
    libnet_destroy(libnet_handle);
}//end anubis_write_data_link_or_network

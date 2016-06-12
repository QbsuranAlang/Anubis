//
//  anubis_writer.c
//  Anubis
//
//  Created by 聲華 陳 on 2016/4/1.
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

static u_int16_t anubis_checksum(u_int16_t *data, int len) {
    u_int32_t sum = 0;
    
    for (; len > 1; len -= 2) {
        sum += *data++;
        if (sum & 0x80000000)
            sum = (sum & 0xffff) + (sum >> 16);
    }
    
    if (len == 1) {
        u_int16_t i = 0;
        *(u_int8_t*) (&i) = *(u_int8_t *) data;
        sum += i;
    }
    
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    
    return ~sum;
}

void anubis_wait_microsecond(u_int32_t microsecond) {
    anubis_verbose("Sleep for %d microsecond%s", microsecond, microsecond ? "s\n" : "\n");
    struct timeval delay = { microsecond / 1000000, microsecond % 1000000 };
    select(0, NULL, NULL, NULL, &delay);

    /*
     //sometimes don't work
    unsigned long nsec = microsecond * 1000;
    struct timespec delay = { nsec / 1000000000, nsec % 1000000000 };
    pselect(0, NULL, NULL, NULL, &delay, NULL);
    */
    
}//end anubis_wait_microsecond

static void anubis_build_headers(libnet_t *handle, anubis_packet_t *packet) {
    
#define FUNCTION_TAIL \
payload ? top_protocol ? payload->data : NULL : NULL, \
payload ? top_protocol ? payload->data_length : 0 : 0, \
handle, \
LIBNET_PTAG_INITIALIZER
    
#define DO_PAYLOAD() \
if(payload && top_protocol) { \
    top_protocol = 0; \
}

#define PROTOCOL protocol->u
    
    anubis_packet_raw_data_t *payload = NULL;
    int top_protocol = 1;
    
    //icmp redirect only need the first 8 bytes, damn
    int icmp_redirect = 0;
    for(int i = 0 ; i < packet->layers ; i++) {
        anubis_protocol_t *protocol = &packet->protocols[i];
        if(protocol->protocol_type == anubis_icmp && PROTOCOL.icmp.icmp_type == ICMP_REDIRECT) {
            
            //out of range
            if(i + 2 > packet->layers - 1)
                break;
            
            icmp_redirect = 1;
            
            anubis_protocol_t *data = &packet->protocols[i + 2];
            if(packet->protocols[i + 1].protocol_type == anubis_ip) {
                struct libnet_ipv4_hdr *ip = &packet->protocols[i + 1].u.ip;
                
                //correct the byte order of the first 8 bytes only
                switch (ip->ip_p) {
                    case IPPROTO_UDP: {
                        struct libnet_udp_hdr *udp = &data->u.udp;
                        udp->uh_dport = htons(udp->uh_dport);
                        udp->uh_sport = htons(udp->uh_sport);
                        udp->uh_ulen = htons(udp->uh_ulen);
                        udp->uh_sum = ntohs(udp->uh_sum);
                        if(udp->uh_sum == 0) {
                            udp->uh_sum = anubis_checksum((u_int16_t *)udp, LIBNET_ICMPV4_REDIRECT_H);
                        }//end if
                    }
                        break;
                    case IPPROTO_TCP: {
                        struct libnet_tcp_hdr *tcp = &data->u.tcp;
                        tcp->th_sport = htons(tcp->th_sport);
                        tcp->th_dport = htons(tcp->th_dport);
                        tcp->th_seq = htonl(tcp->th_seq);
                    }
                        break;
                    case IPPROTO_ICMP: {
                        anubis_icmp_t *icmp = &data->u.icmp;
                        icmp->icmp_cksum = ntohs(icmp->icmp_cksum);
                        if(icmp->icmp_cksum == 0) {
                            icmp->icmp_cksum = anubis_checksum((u_int16_t *)icmp, LIBNET_ICMPV4_REDIRECT_H);
                        }//end if
                        if(icmp->icmp_type == ICMP_ECHO || icmp->icmp_type == ICMP_ECHOREPLY) {
                            icmp->icmp_id = htons(icmp->icmp_id);
                            icmp->icmp_seq = htons(icmp->icmp_seq);
                        }//end if
                        if(icmp->icmp_type == ICMP_UNREACH && icmp->icmp_code == ICMP_UNREACH_NEEDFRAG) {
                            icmp->icmp_nextmtu = htons(icmp->icmp_nextmtu);
                        }//end if
                    }
                        break;
                }//end switch
            }//end if
            
            payload = (anubis_packet_raw_data_t *)malloc(sizeof(*payload));
            memset(payload, 0, sizeof(*payload));
            
            payload->data = (u_int8_t *)&data->u;
            payload->data_length = LIBNET_ICMPV4_REDIRECT_H;
            packet->layers -= 1; //ingore the last one
            
            break;
        }//end if
    }//end for icmp redirect
    
    libnet_ptag_t tag = 0;
    int ip_options_length = 0;
    for(int i = packet->layers - 1 ; i >= 0 ; i--) {
        anubis_protocol_t *protocol = &packet->protocols[i];
        switch (protocol->protocol_type) {
            case anubis_ethernet:
                tag =
                libnet_build_ethernet(PROTOCOL.ethernet.ether_dhost,
                                      PROTOCOL.ethernet.ether_shost,
                                      PROTOCOL.ethernet.ether_type,
                                      FUNCTION_TAIL);
                if(tag == -1)
                    anubis_err("%s\n", libnet_geterror(handle));
                DO_PAYLOAD();
                break;
                
            case anubis_arp:
                tag =
                libnet_build_arp(PROTOCOL.arp.arp_hrd,
                                 PROTOCOL.arp.arp_pro,
                                 PROTOCOL.arp.arp_hln,
                                 PROTOCOL.arp.arp_pln,
                                 PROTOCOL.arp.arp_op,
                                 PROTOCOL.arp.arp_sha,
                                 PROTOCOL.arp.arp_spa,
                                 PROTOCOL.arp.arp_tha,
                                 PROTOCOL.arp.arp_tpa,
                                 FUNCTION_TAIL);
                if(tag == -1)
                    anubis_err("%s\n", libnet_geterror(handle));
                DO_PAYLOAD();
                break;
                
            case anubis_wol:
                
                if(payload && top_protocol) {
                    tag = libnet_build_data((const u_int8_t *)payload->data,
                                            payload->data_length,
                                            handle, LIBNET_PTAG_INITIALIZER);
                    
                    if(tag == -1)
                        anubis_err("%s", libnet_geterror(handle));
                }//end if not build payload
                
                tag = libnet_build_data((const uint8_t *)&PROTOCOL.wol,
                                        ANUBIS_WOL_H,
                                        handle, LIBNET_PTAG_INITIALIZER);
                
                if(tag == -1)
                    anubis_err("%s", libnet_geterror(handle));
                
                DO_PAYLOAD();
                break;
                
            case anubis_ip:
                tag =
                libnet_build_ipv4(PROTOCOL.ip.ip_len == 0 ?
                                  handle->total_size + LIBNET_IPV4_H + ip_options_length : PROTOCOL.ip.ip_len,
                                  PROTOCOL.ip.ip_tos,
                                  PROTOCOL.ip.ip_id,
                                  PROTOCOL.ip.ip_off,
                                  PROTOCOL.ip.ip_ttl,
                                  PROTOCOL.ip.ip_p,
                                  PROTOCOL.ip.ip_sum,
                                  PROTOCOL.ip.ip_src.s_addr,
                                  PROTOCOL.ip.ip_dst.s_addr,
                                  FUNCTION_TAIL);
                if(tag == -1)
                    anubis_err("%s\n", libnet_geterror(handle));
                DO_PAYLOAD();
                break;
                
            case anubis_ip_option:
                ip_options_length = PROTOCOL.ip_options.options_length;
                tag =
                libnet_build_ipv4_options(PROTOCOL.ip_options.options,
                                          PROTOCOL.ip_options.options_length,
                                          handle, LIBNET_PTAG_INITIALIZER);
                if(tag == -1)
                    anubis_err("%s\n", libnet_geterror(handle));
                DO_PAYLOAD();
                break;
                
            case anubis_udp:
                tag =
                libnet_build_udp(PROTOCOL.udp.uh_sport,
                                 PROTOCOL.udp.uh_dport,
                                 PROTOCOL.udp.uh_ulen == 0 ? handle->total_size + LIBNET_UDP_H : PROTOCOL.udp.uh_ulen,
                                 PROTOCOL.udp.uh_sum,
                                 FUNCTION_TAIL);
                if(tag == -1)
                    anubis_err("%s\n", libnet_geterror(handle));
                DO_PAYLOAD();
                break;
                
            case anubis_tcp:
                tag =
                libnet_build_tcp(PROTOCOL.tcp.th_sport,
                                 PROTOCOL.tcp.th_dport,
                                 PROTOCOL.tcp.th_seq,
                                 PROTOCOL.tcp.th_ack,
                                 PROTOCOL.tcp.th_flags,
                                 PROTOCOL.tcp.th_win,
                                 PROTOCOL.tcp.th_sum,
                                 PROTOCOL.tcp.th_urp,
                                 PROTOCOL.tcp.th_off << 2,
                                 FUNCTION_TAIL);
                if(tag == -1)
                    anubis_err("%s\n", libnet_geterror(handle));
                DO_PAYLOAD();
                break;
                
            case anubis_tcp_option:
                tag =
                libnet_build_tcp_options(PROTOCOL.tcp_options.options,
                                         PROTOCOL.tcp_options.options_length,
                                         handle, LIBNET_PTAG_INITIALIZER);
                if(tag == -1)
                    anubis_err("%s\n", libnet_geterror(handle));
                DO_PAYLOAD();
                break;
                
            case anubis_icmp:
                switch (PROTOCOL.icmp.icmp_type) {
                    case ICMP_ECHO:
                    case ICMP_ECHOREPLY:
                        tag =
                        libnet_build_icmpv4_echo(PROTOCOL.icmp.icmp_type,
                                                 PROTOCOL.icmp.icmp_code,
                                                 PROTOCOL.icmp.icmp_cksum,
                                                 PROTOCOL.icmp.icmp_id,
                                                 PROTOCOL.icmp.icmp_seq,
                                                 FUNCTION_TAIL);
                        
                        if(tag == -1)
                            anubis_err("%s\n", libnet_geterror(handle));
                        break;
                        
                    case ICMP_TIMXCEED:
                        tag =
                        libnet_build_icmpv4_timeexceed(PROTOCOL.icmp.icmp_type,
                                                       PROTOCOL.icmp.icmp_code,
                                                       PROTOCOL.icmp.icmp_cksum,
                                                       FUNCTION_TAIL);
                        if(tag == -1)
                            anubis_err("%s\n", libnet_geterror(handle));
                        break;
                        
                    case ICMP_UNREACH:
                        tag =
                        anubis_build_icmpv4_unreach(PROTOCOL.icmp.icmp_type,
                                                    PROTOCOL.icmp.icmp_code,
                                                    PROTOCOL.icmp.icmp_cksum,
                                                    PROTOCOL.icmp.icmp_nextmtu,
                                                    FUNCTION_TAIL);
                        if(tag == -1)
                            anubis_err("%s\n", libnet_geterror(handle));
                        break;
                        
                    case ICMP_REDIRECT:
                        tag =
                        libnet_build_icmpv4_redirect(PROTOCOL.icmp.icmp_type,
                                                     PROTOCOL.icmp.icmp_code,
                                                     PROTOCOL.icmp.icmp_cksum,
                                                     PROTOCOL.icmp.icmp_gwaddr.s_addr,
                                                     FUNCTION_TAIL);
                        if(tag == -1)
                            anubis_err("%s\n", libnet_geterror(handle));
                        break;
                        
                    default:
                        anubis_err("anubis_build_headers(): \"%d\" unknown ICMPv4 type\n", PROTOCOL.icmp.icmp_type);
                        break;
                }//end switch
                
                DO_PAYLOAD();
                break;
                
            case anubis_rip:
                tag =
                anubis_build_rip((const u_int8_t *)PROTOCOL.rip.data,
                                 PROTOCOL.rip.data_length,
                                 FUNCTION_TAIL);
                if(tag == -1)
                    anubis_err("%s\n", libnet_geterror(handle));
                
                DO_PAYLOAD();
                break;
                
            case anubis_ssdp:
                tag =
                anubis_build_ssdp((const u_int8_t *)PROTOCOL.ssdp.data,
                                  PROTOCOL.ssdp.length,
                                  FUNCTION_TAIL);
                
                if(tag == -1)
                    anubis_err("%s", libnet_geterror(handle));
                
                DO_PAYLOAD();
                break;
                
            case anubis_http:
                tag =
                anubis_build_http((const u_int8_t *)PROTOCOL.http.data,
                                  PROTOCOL.http.length,
                                  FUNCTION_TAIL);
                
                if(tag == -1)
                    anubis_err("%s", libnet_geterror(handle));
                
                DO_PAYLOAD();
                break;
                
            case anubis_dhcp:
                tag = libnet_build_dhcpv4(PROTOCOL.dhcp.dhcp_opcode,
                                          PROTOCOL.dhcp.dhcp_htype,
                                          PROTOCOL.dhcp.dhcp_hlen,
                                          PROTOCOL.dhcp.dhcp_hopcount,
                                          PROTOCOL.dhcp.dhcp_xid,
                                          PROTOCOL.dhcp.dhcp_secs,
                                          PROTOCOL.dhcp.dhcp_flags,
                                          ntohl(PROTOCOL.dhcp.dhcp_cip),
                                          ntohl(PROTOCOL.dhcp.dhcp_yip),
                                          ntohl(PROTOCOL.dhcp.dhcp_sip),
                                          ntohl(PROTOCOL.dhcp.dhcp_gip),
                                          PROTOCOL.dhcp.dhcp_chaddr,
                                          PROTOCOL.dhcp.dhcp_sname,
                                          PROTOCOL.dhcp.dhcp_file,
                                          FUNCTION_TAIL);
                
                if(tag == -1)
                    anubis_err("%s\n", libnet_geterror(handle));
                
                DO_PAYLOAD();
                break;
                
            case anubis_dhcp_option:
                tag = anubis_build_dhcp_options(PROTOCOL.dhcp_options.options,
                                                PROTOCOL.dhcp_options.options_length,
                                                FUNCTION_TAIL);
            
                if(tag == -1)
                    anubis_err("%s", libnet_geterror(handle));
                DO_PAYLOAD();
                break;
                
            case anubis_raw_data:
                tag = anubis_build_raw_data(PROTOCOL.raw_data.data,
                                            PROTOCOL.raw_data.data_length,
                                            FUNCTION_TAIL);
                
                if(tag == -1)
                    anubis_err("%s", libnet_geterror(handle));
                DO_PAYLOAD();
                break;
                
            case anubis_payload:
                if(!payload)
                    payload = &PROTOCOL.payload;
                break;
                
            default:
                anubis_err("anubis_build_headers(): It is never should be happened\n");
                break;
        }//end switch
    }//end for
    
    //correct it
    if(icmp_redirect) {
        packet->layers += 1;
        free(payload);
    }//end if
    
    if(payload && handle->total_size == 0 && top_protocol && payload->data && payload->data_length) {
        tag = libnet_build_data((const u_int8_t *)payload->data,
                                payload->data_length,
                                handle, LIBNET_PTAG_INITIALIZER);
        
        if(tag == -1)
            anubis_err("%s", libnet_geterror(handle));
    }//end not build payload
    
#undef FUNCTION_TAIL
#undef DO_PAYLOAD
#undef PROTOCOL
    
}//end anubis_build_headers

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
    }
    
    libnet_handle = anubis_libnet_init(libnet_type, config->device, errbuf);
    
    if(!libnet_handle) {
        anubis_err("%s\n", errbuf);
        return;
    }//end if
    
    if(config->comment)
        anubis_out("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
    
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
                
                anubis_out("Sending packet\n");
                int ret = libnet_write(libnet_handle);
                if(ret <= 0) {
                    anubis_err("libnet_write(): %s\n", libnet_geterror(libnet_handle));
                }//end if
                else {
                    anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                    if(packet->dump_send)
                        anubis_dump_libnet_content(libnet_handle, 0, 0);
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
    
    //free
    libnet_destroy(libnet_handle);
}//end anubis_write_data_link_or_network

/**
 http://stackoverflow.com/questions/20616029/os-x-equivalent-of-so-bindtodevice
 */
int anubis_bind_to_device(int sock, int family, const char *devicename, u_int16_t port) {
#ifdef WIN32
	return 0;

#else
    struct ifaddrs *pList = NULL;
    struct ifaddrs *pAdapter = NULL;
    struct sockaddr_in pAdapterFound = {0};
    int bindresult = -1;
    int found = 0;
    
    int result = getifaddrs(&pList);
    if (result < 0) {
        anubis_perror("getifaddrs()");
        return -1;
    }//end if
    
    pAdapter = pList;
    while (pAdapter) {
        if ((pAdapter->ifa_addr != NULL) &&
            (pAdapter->ifa_name != NULL) &&
            (family == pAdapter->ifa_addr->sa_family)) {
            if (devicename && !strcmp(pAdapter->ifa_name, devicename)) {
                memmove(&pAdapterFound, pAdapter->ifa_addr, sizeof(pAdapterFound));
                found = 1;
                break;
            }//end if
        }//end if
        pAdapter = pAdapter->ifa_next;
    }//end while
    
    //device is given, but not found
    if(devicename && !found) {
        anubis_err("anubis_bind_to_device(): \"%s\" is not found\n", devicename);
        return -1;
    }//end if
    if(!devicename && found) {
        anubis_err("anubis_bind_to_device(): It is never should be happened\n");
        return -1;
    }//end if
    
    int addrsize = (family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    pAdapterFound.sin_family = family; //always bind to chosen address type
#ifndef __linux
    pAdapterFound.sin_len = sizeof(struct sockaddr_in);
#endif
    pAdapterFound.sin_port = htons(port);

    //if device is given and found, bind to device_addr:port
    
    //if device is not given and not found, bind to 0.0.0.0:port
    /*if not found, pAdapterFound.sin_addr is still zero, so address is also 0.0.0.0
      in that case, it will bind to 0.0.0.0:port*/
    
    //other condition will never reach here
    //if device is not given and found, never happen
    //if device is given and not found, device is not found
    
    bindresult = bind(sock, (struct sockaddr *)&pAdapterFound, addrsize);
    if(bindresult == -1) {
        anubis_perror("bind()");
    }//end if
    else {
        if(devicename)
            anubis_verbose("Binded to \"%s\"\n", devicename);
        else if(port)
            anubis_verbose("Binded to \"%s:%d\"\n",
                           pAdapterFound.sin_addr.s_addr == 0 || pAdapterFound.sin_addr.s_addr == htonl(INADDR_LOOPBACK) ?
                           "localhost" :
                           anubis_ip_ntoa(pAdapterFound.sin_addr.s_addr), port);
        else
            anubis_verbose("Binded to \"%s\"\n",
                           pAdapterFound.sin_addr.s_addr == 0 || pAdapterFound.sin_addr.s_addr == htonl(INADDR_LOOPBACK) ?
                           "localhost" :
                           anubis_ip_ntoa(pAdapterFound.sin_addr.s_addr));
    }//end else
    
    freeifaddrs(pList);
    
    return bindresult;
#endif
}//end anubis_bind_to_device

static int anubis_set_socket_option(anubis_t *config, int sd) {
    
#if !(WIN32)
    int n = 1;
#if (__svr4__)
    void *nptr = &n;
#else
    int *nptr = &n;
#endif  /* __svr4__ */
#else
    BOOL n;
	char *nptr = (char *)&n;
#endif
    int len;
    
#ifdef SO_SNDBUF
    
    /*
     * man 7 socket
     *
     * Sets and  gets  the  maximum  socket  send buffer in bytes.
     *
     * Taken from libnet
     */
    anubis_verbose("Setting socket option: \"SO_SNDBUF\"\n");
    len = sizeof(n);
    if (getsockopt(sd, SOL_SOCKET, SO_SNDBUF, &n, (socklen_t *)&len) < 0) {
        anubis_perror("getsockopt(): get SO_SNDBUF failed");
        close(sd);
        return -1;
    }//end if
    
    for (n += 128; n < 1048576; n += 128) {
        if (setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &n, len) < 0) {
            if (errno == ENOBUFS) {
                break;
            }
            anubis_perror("setsockopt(): set SO_SNDBUF failed");
            close(sd);
            continue;
        }
    }//end for
#endif
    
#ifdef SO_RCVBUF
    
    /*
     * man 7 socket
     *
     * Sets and  gets  the  maximum  socket  receive buffer in bytes.
     *
     * Taken from libnet
     */
    anubis_verbose("Setting socket option: \"SO_RCVBUF\"\n");
    len = sizeof(n);
    if (getsockopt(sd, SOL_SOCKET, SO_RCVBUF, &n, (socklen_t *)&len) < 0) {
        anubis_perror("getsockopt(): get SO_RCVBUF failed");
        close(sd);
        return -1;
    }//end if
    
    for (n += 128; n < 1048576; n += 128) {
        if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &n, len) < 0) {
            if (errno == ENOBUFS) {
                break;
            }
            anubis_perror("setsockopt(): set SO_RCVBUF failed");
            close(sd);
            continue;
        }
    }//end for
#endif
    
#ifdef SO_BROADCAST
    /*
     * man 7 socket
     *
     * Set or get the broadcast flag. When  enabled,  datagram  sockets
     * receive packets sent to a broadcast address and they are allowed
     * to send packets to a broadcast  address.   This  option  has  no
     * effect on stream-oriented sockets.
     */
    anubis_verbose("Setting socket option: \"SO_BROADCAST\"\n");
    if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, nptr, sizeof(n)) == -1) {
        anubis_perror("setsockopt(): set SO_BROADCAST failed");
        close(sd);
        return -1;
    }//ned if
#endif  /*  SO_BROADCAST  */
    
    /*bind to device*/
    if(anubis_bind_to_device(sd, AF_INET,
                             config->device,
                             config->socket_type == anubis_transport_socket ? 0 : config->src_port) == -1) {
        close(sd);
        return -1;
    }//end if
    
    
    if(config->type == SOCK_DGRAM || config->type == SOCK_STREAM) {
        n = 1;
        anubis_verbose("Setting socket option: \"SO_REUSEADDR\"\n");
        if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (const void*) nptr, (socklen_t) sizeof(n)) == -1) {
            anubis_perror("setsockopt(): set SO_REUSEADDR failed");
            close(sd);
            return -1;
        }
        
#if ((SO_REUSEPORT) && !(WIN32))
        anubis_verbose("Setting socket option: \"SO_REUSEPORT\"\n");
        if(setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, (const void*) nptr, (socklen_t) sizeof(n)) == -1) {
            anubis_perror("setsockopt(): set SO_REUSEPORT failed");
            close(sd);
            return -1;
        }
#endif
    }
    
    //add to multicast group
    if(config->type == SOCK_DGRAM && config->muliticast_groups) {
        struct ifaddrs *pList = NULL;
        struct ifaddrs *pAdapter = NULL;
        struct sockaddr_in pAdapterFound = {0};
#ifdef WIN32
        //windows
#else
        int result = getifaddrs(&pList);
        
        if (result < 0) {
            anubis_perror("getifaddrs()");
            close(sd);
            return -1;
        }//end if
        
        pAdapter = pList;
        while (pAdapter) {
            if ((pAdapter->ifa_addr != NULL) &&
                (pAdapter->ifa_name != NULL) &&
                (AF_INET == pAdapter->ifa_addr->sa_family)) {
                if (config->device && !strcmp(pAdapter->ifa_name, config->device)) {
                    memmove(&pAdapterFound, pAdapter->ifa_addr, sizeof(pAdapterFound));
                    break;
                }//end if
            }//end if
            pAdapter = pAdapter->ifa_next;
        }//end while
        
        freeifaddrs(pList);
#endif
        struct ip_mreq mreq = {0};
        memmove(&mreq.imr_interface, &pAdapterFound.sin_addr, sizeof(mreq.imr_interface));
        
        for(int i = 0 ; i < config->muliticast_groups_length ; i++) {
            in_addr_t multicast_address = config->muliticast_groups[i];
            
            anubis_verbose("Setting socket option: \"IP_ADD_MEMBERSHIP\"\n");
            anubis_verbose("Adding %s to multicast group\n", anubis_ip_ntoa(multicast_address));
            memmove(&mreq.imr_multiaddr, &multicast_address, sizeof(mreq.imr_multiaddr));
            if(setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
                anubis_perror("setsockopt(): set IP_ADD_MEMBERSHIP failed");
                close(sd);
                return -1;
            }//end if
        }//end for
    }
    
    return sd;
}//end anubis_set_socket_option

static int anubis_build_fake_header(anubis_t *config,
                                    libnet_t *libnet_handle,
                                    int proto,
                                    int build_transport,
                                    int build_network) {
    
    if(build_transport) {
        if(proto == IPPROTO_UDP) {
            //build fake udp
            libnet_ptag_t tag =
            libnet_build_udp(config->src_port,
                             config->dst_port,
                             LIBNET_UDP_H + libnet_handle->total_size,
                             0,
                             NULL, 0,
                             libnet_handle, LIBNET_PTAG_INITIALIZER);
            
            if(tag == -1) {
                anubis_err(" %s\n", libnet_geterror(libnet_handle));
                return -1;
            }//end if
        }//end if fake udp
        else if(proto == IPPROTO_TCP) {
            //build fake tcp
            libnet_ptag_t tag =
            libnet_build_tcp(config->src_port,
                             config->dst_port,
                             0,
                             0,
                             0,
                             0,
                             0,
                             0,
                             LIBNET_TCP_H,
                             NULL, 0,
                             libnet_handle, LIBNET_PTAG_INITIALIZER);
            if(tag == -1) {
                anubis_err("%s\n", libnet_geterror(libnet_handle));
                return -1;
            }//end if
        }//end if fake tcp
        else {
            anubis_err("anubis_build_fake_header(): Unknown protocol: %d\n", proto);
            return -1;
        }//end if
    }//end build fake transport
    
    if(build_network) {
        //build fake ip header
        struct libnet_ipv4_hdr ip_hdr = anubis_default_ip_header(config->device);
        ip_hdr.ip_dst.s_addr = config->dst_ip;
        ip_hdr.ip_p = proto;
        
        libnet_ptag_t tag =
        libnet_build_ipv4(libnet_handle->total_size + LIBNET_IPV4_H,
                          ip_hdr.ip_tos,
                          ip_hdr.ip_id,
                          ip_hdr.ip_off,
                          ip_hdr.ip_ttl,
                          ip_hdr.ip_p,
                          ip_hdr.ip_sum,
                          ip_hdr.ip_src.s_addr,
                          ip_hdr.ip_dst.s_addr,
                          NULL, 0,
                          libnet_handle, LIBNET_PTAG_INITIALIZER);
        
        if(tag == -1) {
            anubis_err("%s\n", libnet_geterror(libnet_handle));
            return -1;
        }//end if
    }//end build fake network
    
    return 0;
}//end anubis_build_fake_header

void anubis_write_transport(anubis_t *config) {
    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    u_int64_t inner_amount = 0;
    u_int64_t outter_amount = 0;
    libnet_t *libnet_handle = NULL;
    struct sockaddr_in sin = {0};
#ifndef WIN32
    int sd;
#else
    SOCKET sd;
#endif
    
    libnet_handle = anubis_libnet_init(LIBNET_RAW4, config->device, errbuf);
    
    if(!libnet_handle) {
        anubis_err("%s\n", errbuf);
        return;
    }//end if
    
    if(config->comment)
        anubis_out("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
    
    //dst
    memset(&sin, 0, sizeof(sin));
    sin.sin_family  = AF_INET;
    sin.sin_addr.s_addr = config->dst_ip;
    
    //open socket
    sd = socket(AF_INET, SOCK_RAW, config->protocol);
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
            
#if 0
            /* set port for TCP */
            /*
             *  XXX - should first check to see if there's a pblock for a TCP
             *  header, if not we can use a dummy value for the port.
             */
            if (ip_hdr.ip_p == IPPROTO_TCP) {
                struct libnet_tcp_hdr *tcph_p =
                (struct libnet_tcp_hdr *)(packet + (ip_hdr.ip_hl << 2));
                sin.sin_port = tcph_p->th_dport;
            }
            /* set port for UDP */
            /*
             *  XXX - should first check to see if there's a pblock for a UDP
             *  header, if not we can use a dummy value for the port.
             */
            else if (ip_hdr.ip_p == IPPROTO_UDP) {
                struct libnet_udp_hdr *udph_p =
                (struct libnet_udp_hdr *)(packet + (ip_hdr.ip_hl << 2));
                sin.sin_port = udph_p->uh_dport;
            }
#endif /* WIN32 */
            
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
                
                anubis_out("Sending packet\n");
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
            
            //free
            if (libnet_handle->aligner > 0) {
                content = content - libnet_handle->aligner;
            }//end if
            free(content);
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


static void anubis_write_datagram(anubis_t *config) {
    
    if(config->security_socket) {
        anubis_err("TUTU: Someday I will finish it, disabled \"Security\"\n");
        config->security_socket = 0;
    }
    
    if(config->security_socket) {
        /*
        u_int64_t outter_amount = 0;
        struct timeval timeout;
        struct sockaddr_in server_sin = {0};
        struct sockaddr_in client_sin = {0};
        
#ifndef WIN32
        int sd;
#else
        SOCKET sd;
#endif
        
        SSL_CTX *ctx = NULL;
        
        if(config->comment)
            anubis_out("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
        
        if(config->security_socket) {
            SSL_load_error_strings();
            SSLeay_add_ssl_algorithms();
            const SSL_METHOD *meth = anubis_string_to_SSL_METOHD(config->sslMethod, config->role);
            if(!meth)
                return;
            ctx = SSL_CTX_new(meth);
            if (!ctx) {
                anubis_ssl_perror("SSL_CTX_new()");
                return;
            }//end if
            
            //load ceritificate
            if (SSL_CTX_use_certificate_file(ctx, config->certificate_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_certificate_file()");
                if(config->role == ANUBIS_ROLE_SERVER)
                    return;
            }//end if
            
            //load private key
            if (SSL_CTX_use_PrivateKey_file(ctx, config->private_key_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_PrivateKey_file()");
                if(config->role == ANUBIS_ROLE_SERVER)
                    return;
            }//end if
            
            if (!SSL_CTX_check_private_key(ctx)) {
                anubis_err("Socket[%d] Private key does not match the certificate public key\n", config->index);
                if(config->role == ANUBIS_ROLE_SERVER)
                    return;
            }//end if
        }
        
        
        //open socket
        sd = socket(AF_INET, config->type, 0);
        //set socket option
        sd = anubis_set_socket_option(config, sd, 1);
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
         
            //set outter timeout
#ifdef SO_SNDTIMEO
            memset(&timeout, 0, sizeof(timeout));
            timeout.tv_sec = config->send_timeout / 1000;
            timeout.tv_usec = config->send_timeout % 1000;
            if(config->send_timeout) {
                anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
                if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
                    anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
                    close(sd);
                    return;
                }
            }//end if
#endif
            
#ifdef SO_RCVTIMEO
            memset(&timeout, 0, sizeof(timeout));
            timeout.tv_sec = config->recv_timeout / 1000;
            timeout.tv_usec = config->recv_timeout % 1000;
            if(config->recv_timeout) {
                anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
                if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                    anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
                    close(sd);
                    return;
                }
            }//end if
#endif
            
            if(config->role == ANUBIS_ROLE_SERVER) {
                memset(&client_sin, 0, sizeof(client_sin));
                SSL *ssl = SSL_new(ctx);
                
                anubis_out("Waiting client...\n");
                while (DTLSv1_listen(ssl, &client_sin) <= 0);
                
                if(config->asynchronous) {
                    pid_t pid = fork();
                    if(pid == 0) {
                        //here
                        printf("here\n");
                        exit(0);
                    }//end if
                    else if(pid == -1) {
                        anubis_perror("fork()");
                        continue;
                    }//end else
                }//end if
                else {
                    //here
                    printf("here\n");
                }//end else
                
            }//end if server
        }//end while outter
        
        close(sd);
        if(ctx)
            SSL_CTX_free(ctx);
        */
    }
    else {
        char errbuf[LIBNET_ERRBUF_SIZE] = {0};
        u_int64_t inner_amount = 0;
        u_int64_t outter_amount = 0;
        libnet_t *libnet_handle = NULL;
        
        struct timeval timeout;
#ifndef WIN32
        int sd;
#else
        SOCKET sd;
#endif
        int len;
        
        libnet_handle = anubis_libnet_init(LIBNET_RAW4, config->device, errbuf);
        
        if(!libnet_handle) {
            anubis_err("%s\n", errbuf);
            return;
        }//end if
        
        if(config->comment)
            anubis_out("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
        
        //open socket
        sd = socket(AF_INET, config->type, 0);
        
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
            
            //set outter timeout
#ifdef SO_SNDTIMEO
            memset(&timeout, 0, sizeof(timeout));
            timeout.tv_sec = config->send_timeout / 1000;
            timeout.tv_usec = config->send_timeout % 1000;
            if(config->send_timeout) {
                anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
                if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
                    anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
                    close(sd);
                    return;
                }
            }//end if
#endif
            
#ifdef SO_RCVTIMEO
            memset(&timeout, 0, sizeof(timeout));
            timeout.tv_sec = config->recv_timeout / 1000;
            timeout.tv_usec = config->recv_timeout % 1000;
            if(config->recv_timeout) {
                anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
                if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                    anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
                    close(sd);
                    return;
                }
            }//end if
#endif
            
            //peer packet injection
            for(int i = 0 ; i < config->packets_count ; i++) {
                
                anubis_packet_t *packet = &config->packets[i];
                
                uint32_t content_length = 0;
                uint8_t *content = NULL;
                
                //set intter timeout
#ifdef SO_SNDTIMEO
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = packet->send_timeout / 1000;
                timeout.tv_usec = packet->send_timeout % 1000;
                if(packet->send_timeout) {
                    anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
                    if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
                        anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
                        close(sd);
                        return;
                    }
                }//end if
#endif
                
#ifdef SO_RCVTIMEO
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = packet->recv_timeout / 1000;
                timeout.tv_usec = packet->recv_timeout % 1000;
                if(packet->recv_timeout) {
                    anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
                    if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                        anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
                        close(sd);
                        return;
                    }
                }//end if
#endif
                
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
                    
                    if(packet->out_going) {
                        
                        if(!config->dst_ip && config->role == ANUBIS_ROLE_SERVER) {
                            anubis_err("Socket[%d] \"Receive Packet\" should be call before \"Send Packet\", skip the \"Send Packet\"\n", config->index);
                            continue;
                        }//end if
                        
                        if(packet->interactive) {
                            
                            struct sockaddr_in dst_sin = {0};
                            dst_sin.sin_family = AF_INET;
                            dst_sin.sin_addr.s_addr = config->dst_ip;
                            dst_sin.sin_port = htons(config->dst_port);
#if !(__linux) && !(WIN32)
							dst_sin.sin_len = sizeof(dst_sin);
#endif
                            anubis_out("Send to %s:%d\n", anubis_ip_ntoa(dst_sin.sin_addr.s_addr), ntohs(dst_sin.sin_port));
                            anubis_out("Interactive on(EOF to finish):\n");
                            char buffer[65535] = {0};
                            anubis_in(buffer, sizeof(buffer));
                            anubis_out("Read: %*s[EOF]\n", (int)strlen(buffer), buffer);
                            anubis_out("Length: %d\n", (int)strlen(buffer));
                            if(strlen(buffer) == 0) {
                                anubis_out("Not read anything\n");
                                continue;
                            }//end if
                            
                            int ret = (int)sendto(sd, buffer,
                                                  packet->send_length ? packet->send_length :
                                                  strlen(buffer),
                                                  0, (struct sockaddr *)&dst_sin, sizeof(dst_sin));
                            
                            if(ret < 0) {
                                anubis_perror("sendto()");
                            }//end if
                            else {
                                anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                                if(packet->dump_send)
                                    anubis_dump_application(buffer, (u_int32_t)strlen(buffer));
                            }//end else
                            
                        }//end if interactive
                        else if(packet->input_filename) {
                            struct sockaddr_in dst_sin = {0};
                            dst_sin.sin_family = AF_INET;
                            dst_sin.sin_addr.s_addr = config->dst_ip;
                            dst_sin.sin_port = htons(config->dst_port);
#if !(__linux) && !(WIN32)
                            dst_sin.sin_len = sizeof(dst_sin);
#endif
                            anubis_out("Send to %s:%d\n", anubis_ip_ntoa(dst_sin.sin_addr.s_addr), ntohs(dst_sin.sin_port));
                            anubis_out("Read from file: %s\n", packet->input_filename);
                            char buffer[65535] = {0};
                            
                            //read from file
                            FILE *fp = fopen(packet->input_filename, "r+");
                            if(!fp) {
                                anubis_perror("fopen()");
                                continue;
                            }
                            anubis_in_stream(fp, buffer, sizeof(buffer));
                            fclose(fp);
                            
                            anubis_out("Read: %*s[EOF]\n", (int)strlen(buffer), buffer);
                            anubis_out("Length: %d\n", (int)strlen(buffer));
                            if(strlen(buffer) == 0) {
                                anubis_out("Not read anything\n");
                                continue;
                            }//end if
                            
                            int ret = (int)sendto(sd, buffer,
                                                  packet->send_length ? packet->send_length :
                                                  strlen(buffer),
                                                  0, (struct sockaddr *)&dst_sin, sizeof(dst_sin));
                            
                            if(ret < 0) {
                                anubis_perror("sendto()");
                            }//end if
                            else {
                                anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                                if(packet->dump_send)
                                    anubis_dump_application(buffer, (u_int32_t)strlen(buffer));
                            }//end else
                            
                        }//end if
                        else {
                            
                            libnet_clear_packet(libnet_handle);
                            anubis_build_headers(libnet_handle, packet);
                            if(libnet_handle->total_size == 0 || packet->layers == 0) {
                                anubis_err("Socket[%d] Empty packet\n", config->index);
                                continue;
                            }//end if
                            
                            //build fake header
                            if(anubis_build_fake_header(config, libnet_handle, IPPROTO_UDP, 1, 1) == -1) {
                                continue;
                            }//end if
                            
                            int c;
                            c = libnet_pblock_coalesce(libnet_handle, &content, &content_length);
                            if (c == -1) {
                                anubis_err("libnet_pblock_coalesce(): %s\n", libnet_geterror(libnet_handle));
                                continue;
                            }//end if
                            
                            struct sockaddr_in dst_sin = {0};
                            dst_sin.sin_family = AF_INET;
                            dst_sin.sin_addr.s_addr = config->dst_ip;
                            dst_sin.sin_port = htons(config->dst_port);
#if !(__linux) && !(WIN32)
                            dst_sin.sin_len = sizeof(dst_sin);
#endif
                            
                            anubis_out("Send to %s:%d\n", anubis_ip_ntoa(dst_sin.sin_addr.s_addr), ntohs(dst_sin.sin_port));
                            int ret = (int)sendto(sd, content + LIBNET_IPV4_H + LIBNET_UDP_H,
                                                  packet->send_length ? packet->send_length :
                                                  content_length - LIBNET_IPV4_H - LIBNET_UDP_H,
                                                  0, (struct sockaddr *)&dst_sin, sizeof(dst_sin));
                            if(ret < 0) {
                                anubis_perror("sendto()");
                            }//end if
                            else {
                                anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                                if(packet->dump_send)
                                    anubis_dump_libnet_content(libnet_handle, 1, 1);
                            }//end else
                            
                            //free
                            if (libnet_handle->aligner > 0) {
                                content = content - libnet_handle->aligner;
                            }//end if
                            free(content);
                            content = NULL;
                        }//end else
                        
                        if(config->role == ANUBIS_ROLE_CLIENT) {
                            //maybe next is "Receive packet", this is next source ip address
                            config->src_port = ntohs(config->dst_port);
                        }//end if
                    }//end if send
                    else {
                        
                        if(!config->src_port && config->role == ANUBIS_ROLE_CLIENT) {
                            anubis_err("Socket[%d] \"Send Packet\" should be call before \"Receive Packet\", skip the \"Receive Packet\"\n", config->index);
                            continue;
                        }//end if
                        
                        char buffer[65535] = {0};
                        
                        struct sockaddr_in src_sin = {0};
                        src_sin.sin_family = AF_INET;
                        src_sin.sin_addr.s_addr = INADDR_ANY;
                        src_sin.sin_port = htons(config->src_port);
#if !(__linux) && !(WIN32)
                        src_sin.sin_len = sizeof(src_sin);
#endif
                        anubis_out("Receiving from port localhost:%d\n", config->src_port);
                        len = sizeof(src_sin);
                        
                        int ret = (int)recvfrom(sd, buffer, sizeof(buffer),
                                                0,
                                                (struct sockaddr *)&src_sin, (socklen_t *)&len);
                        
                        if(ret < 0) {
                            if(errno == EAGAIN) {
                                anubis_verbose("Timeout\n");
                                break;
                            }//end if
                            if(errno == EAGAIN && packet->read_until_timeout) {
                                break;
                            }//end if
                            else {
                                anubis_perror("recvfrom()");
                            }//end if
                        }//end if
                        else {
                            anubis_out("Read %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                            if(packet->dump_recv)
                                anubis_dump_application(buffer, ret);
                            
                            if(config->role == ANUBIS_ROLE_SERVER) {
                                //maybe next is "Send packet", this is next destination ip address
                                config->dst_ip = src_sin.sin_addr.s_addr;
                                config->dst_port = ntohs(src_sin.sin_port);
                            }
                            anubis_out("Received from %s:%d\n", anubis_ip_ntoa(src_sin.sin_addr.s_addr), ntohs(src_sin.sin_port));
                            if(packet->output_filename) {
                                anubis_out("Write to %s\n", packet->output_filename);
                                do {
                                    FILE *fp = fopen(packet->output_filename, "a+");
                                    if(!fp) {
                                        anubis_err("fopen()");
                                        break;
                                    }//end if
                                    fprintf(fp, "%*s", ret, buffer);
                                    fflush(fp);
                                    fclose(fp);
                                }
                                while(0);
                            }
                        }//end else
                    }//end if receive
                    
                    if(packet->interval) {
                        anubis_wait_microsecond(packet->interval);
                    }//end if
                }//end while
            }//end for
            
            if(config->interval) {
                anubis_wait_microsecond(config->interval);
            }//end if
        }//end while
        
        //free
        shutdown(sd, SHUT_RDWR);
        close(sd);
        if(libnet_handle)
            libnet_destroy(libnet_handle);
    }
    
}//end anubis_write_datagram

static void anubis_handle_tcp_socket(anubis_t *config, u_int64_t outter_amount, int sd, struct sockaddr_in *sin, SSL_CTX *ctx) {
    if(config->role == ANUBIS_ROLE_SERVER) {
        anubis_out("Client: %s:%d is connected\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
    }
    else if(config->role == ANUBIS_ROLE_CLIENT) {
        anubis_out("Server: %s:%d is connected\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
    }
    
    libnet_t *libnet_handle = NULL;
    u_int64_t inner_amount = 0;
    struct timeval timeout;
    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    SSL *ssl = NULL;
    
    libnet_handle = anubis_libnet_init(LIBNET_RAW4, config->device, errbuf);
    
    if(!libnet_handle) {
        anubis_err("%s\n", errbuf);
        return;
    }//end if
    
    if(config->security_socket) {
        /* ----------------------------------------------- */
        /* TCP connection is ready. Do server side SSL. */
        
        ssl = SSL_new(ctx);
        if(!ssl) {
            anubis_ssl_perror("SSL_new()");
            goto BYE;
        }
        
        if(SSL_set_fd(ssl, sd) <= 0) {
            anubis_ssl_perror("SSL_set_fd()");
            goto BYE;
        }
        
        if(config->role == ANUBIS_ROLE_SERVER) {
            if(SSL_accept(ssl) <= 0) {
                anubis_ssl_perror("SSL_accept()");
                goto BYE;
            }
        }
        else if(config->role == ANUBIS_ROLE_CLIENT) {
            if(SSL_connect(ssl) <= 0) {
                anubis_ssl_perror("SSL_connect()");
                goto BYE;
            }
        }
        if(config->certificate_information && config->role == ANUBIS_ROLE_CLIENT) {
            anubis_dump_server_certificate(ssl);
        }//end if show certficate
    }
    
    //peer packet injection
    for(int i = 0 ; i < config->packets_count ; i++) {
        anubis_packet_t *packet = &config->packets[i];
        
        uint32_t content_length = 0;
        uint8_t *content = NULL;
        
        //set intter timeout
#ifdef SO_SNDTIMEO
        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = packet->send_timeout / 1000;
        timeout.tv_usec = packet->send_timeout % 1000;
        if(packet->send_timeout) {
            anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
            if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
                anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
                close(sd);
                return;
            }
        }//end if
#endif
        
#ifdef SO_RCVTIMEO
        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = packet->recv_timeout / 1000;
        timeout.tv_usec = packet->recv_timeout % 1000;
        if(packet->recv_timeout) {
            anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
            if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
                close(sd);
                return;
            }
        }//end if
#endif
        
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
            
            if(packet->out_going) {
                if(packet->interactive) {
                    anubis_out("Send to %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                    anubis_out("Interactive on(EOF to finish):\n");
                    char buffer[65535] = {0};
                    anubis_in(buffer, sizeof(buffer));
                    anubis_out("Read: %*s[EOF]\n", (int)strlen(buffer), buffer);
                    anubis_out("Length: %d\n", (int)strlen(buffer));
                    if(strlen(buffer) == 0) {
                        anubis_out("Not read anything\n");
                        continue;
                    }//end if
                    
                    int ret = 0;
                    if(!config->security_socket) {
                        ret = (int)send(sd, buffer,
                                        packet->send_length ? packet->send_length :
                                        strlen(buffer),
                                        0);
                    }
                    else {
                        ret = SSL_write(ssl, buffer, packet->send_length ? packet->send_length : (int)strlen(buffer));
                    }
                    
                    if(ret < 0) {
                        if(!config->security_socket)
                            anubis_perror("send()");
                        else
                            anubis_ssl_perror("SSL_write()");
                    }//end if
                    else if(ret == 0) {
                        if(config->role == ANUBIS_ROLE_SERVER) {
                            anubis_out("Connection with client %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                        }
                        else if(config->role == ANUBIS_ROLE_CLIENT) {
                            anubis_out("Connection with server %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                        }
                        goto BYE;
                    }
                    else {
                        anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                        if(packet->dump_send)
                            anubis_dump_application(buffer, (u_int32_t)strlen(buffer));
                    }//end else
                }
                else if(packet->input_filename) {
                    anubis_out("Send to %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                    anubis_out("Read from file: %s\n", packet->input_filename);
                    char buffer[65535] = {0};
                    //read from file
                    FILE *fp = fopen(packet->input_filename, "r+");
                    if(!fp) {
                        anubis_perror("fopen()");
                        continue;
                    }
                    anubis_in_stream(fp, buffer, sizeof(buffer));
                    fclose(fp);
                    anubis_out("Read: %*s[EOF]\n", (int)strlen(buffer), buffer);
                    anubis_out("Length: %d\n", (int)strlen(buffer));
                    if(strlen(buffer) == 0) {
                        anubis_out("Not read anything\n");
                        continue;
                    }//end if
                    
                    int ret = 0;
                    if(!config->security_socket) {
                        ret = (int)send(sd, buffer,
                                        packet->send_length ? packet->send_length :
                                        strlen(buffer),
                                        0);
                    }
                    else {
                        ret = SSL_write(ssl, buffer, packet->send_length ? packet->send_length : (int)strlen(buffer));
                    }
                    
                    if(ret < 0) {
                        if(!config->security_socket)
                            anubis_perror("send()");
                        else
                            anubis_ssl_perror("SSL_write()");
                    }//end if
                    else if(ret == 0) {
                        if(config->role == ANUBIS_ROLE_SERVER) {
                            anubis_out("Connection with client %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                        }
                        else if(config->role == ANUBIS_ROLE_CLIENT) {
                            anubis_out("Connection with server %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                        }
                        goto BYE;
                    }
                    else {
                        anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                        if(packet->dump_send)
                            anubis_dump_application(buffer, (u_int32_t)strlen(buffer));
                    }//end else
                }//end if input from file
                else {
                    libnet_clear_packet(libnet_handle);
                    anubis_build_headers(libnet_handle, packet);
                    if(libnet_handle->total_size == 0 || packet->layers == 0) {
                        anubis_err("Socket[%d] Empty packet\n", config->index);
                        continue;
                    }//end if
                    
                    //build fake header
                    if(anubis_build_fake_header(config, libnet_handle, IPPROTO_TCP, 1, 1) == -1) {
                        continue;
                    }//end if
                    
                    int c;
                    c = libnet_pblock_coalesce(libnet_handle, &content, &content_length);
                    if (c == -1) {
                        anubis_err("libnet_pblock_coalesce(): %s\n", libnet_geterror(libnet_handle));
                        continue;
                    }//end if
                    anubis_out("Send to %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                    
                    int ret = 0;
                    if(!config->security_socket) {
                        ret = (int)send(sd,
                                        content + LIBNET_IPV4_H + LIBNET_TCP_H,
                                        packet->send_length ? packet->send_length :
                                        content_length - LIBNET_IPV4_H - LIBNET_TCP_H,
                                        0);
                    }
                    else {
                        ret = SSL_write(ssl, content + LIBNET_IPV4_H + LIBNET_TCP_H,
                                        packet->send_length ? packet->send_length :
                                        content_length - LIBNET_IPV4_H - LIBNET_TCP_H);
                    }
                    
                    if(ret < 0) {
                        if(!config->security_socket)
                            anubis_perror("send()");
                        else
                            anubis_ssl_perror("SSL_write()");
                    }//end if
                    else if(ret == 0) {
                        goto BYE;
                    }
                    else {
                        anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                        if(packet->dump_send)
                            anubis_dump_libnet_content(libnet_handle, 1, 1);
                    }//end else
                    
                    //free
                    if (libnet_handle->aligner > 0) {
                        content = content - libnet_handle->aligner;
                    }//end if
                    free(content);
                    content = NULL;
                }
            }//end if send
            else {
                
                anubis_out("Receiving from %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                
                char buffer[65535] = {0};
                int ret = 0;
                if(!config->security_socket) {
                    ret = (int)recv(sd, buffer, sizeof(buffer), 0);
                }
                else {
                    ret = SSL_read(ssl, buffer, sizeof(buffer));
                }//end
                
                if(ret < 0) {
                    if(errno == EAGAIN) {
                        anubis_verbose("Timeout\n");
                        break;
                    }//end if
                    if(errno == EAGAIN && packet->read_until_timeout) {
                        break;
                    }//end if
                    else {
                        if(!config->security_socket)
                            anubis_perror("recv()");
                        else
                            anubis_ssl_perror("SSL_read()");
                    }//end if
                }//end if
                else if(ret == 0) {
                    goto BYE;
                }
                else {
                    anubis_out("Read %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                    if(packet->dump_recv)
                        anubis_dump_application(buffer, ret);
                    anubis_out("Received from %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                    if(packet->output_filename) {
                        anubis_out("Write to %s\n", packet->output_filename);
                        do {
                            FILE *fp = fopen(packet->output_filename, "a+");
                            if(!fp) {
                                anubis_err("fopen()");
                                break;
                            }//end if
                            fprintf(fp, "%*s", ret, buffer);
                            fflush(fp);
                            fclose(fp);
                        }
                        while(0);
                    }
                }//end else
                
            }//end receive
            if(packet->interval) {
                anubis_wait_microsecond(packet->interval);
            }//end if
        }//end while
    }//end for
    
BYE:
    if(config->role == ANUBIS_ROLE_SERVER) {
        anubis_out("Connection with client %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
        if(config->asynchronous)
            anubis_out("Waiting client...\n");
    }
    else if(config->role == ANUBIS_ROLE_CLIENT) {
        anubis_out("Connection with server %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
    }
    
    if(ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    shutdown(sd, SHUT_RDWR);
    close(sd);
    if(libnet_handle)
        libnet_destroy(libnet_handle);
}//end anubis_handle_tcp_socket

static void anubis_write_stream(anubis_t *config) {
    u_int64_t outter_amount = 0;
    struct timeval timeout;
    struct sockaddr_in server_sin = {0};
    
#ifndef WIN32
    int sd;
#else
    SOCKET sd;
#endif
    
    SSL_CTX *ctx = NULL;
    
    if(config->comment)
        anubis_out("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
    
    if(config->security_socket) {
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();
        const SSL_METHOD *meth = anubis_string_to_SSL_METOHD(config->sslMethod, config->role);
        if(!meth)
            return;
        ctx = SSL_CTX_new(meth);
        if (!ctx) {
            anubis_ssl_perror("SSL_CTX_new()");
            return;
        }//end if
        
        if(config->role == ANUBIS_ROLE_SERVER) {
            //must use
            if (SSL_CTX_use_certificate_file(ctx, config->certificate_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_certificate_file()");
                return;
            }//end if
            else {
                anubis_verbose("Using certificate: \"%s\"\n", config->certificate_file);
            }
            
            //load private key
            if (SSL_CTX_use_PrivateKey_file(ctx, config->private_key_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_PrivateKey_file()");
                return;
            }//end if
            else {
                anubis_verbose("Using private key: \"%s\"\n", config->private_key_file);
            }
            
            if(!SSL_CTX_check_private_key(ctx)) {
                anubis_err("Socket[%d] Private key does not match the certificate public key\n", config->index);
                return;
            }//end if
        }
        else if(config->role == ANUBIS_ROLE_CLIENT) {
            //must use
            if (config->certificate_file && config->private_key_file &&
                SSL_CTX_use_certificate_file(ctx, config->certificate_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_certificate_file()");
                return;
            }//end if
            else if(config->certificate_file && config->private_key_file) {
                anubis_verbose("Using certificate: \"%s\"\n", config->certificate_file);
            }
            
            //load private key
            if (config->certificate_file && config->private_key_file &&
                SSL_CTX_use_PrivateKey_file(ctx, config->private_key_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_PrivateKey_file()");
                return;
            }//end if
            else if(config->certificate_file && config->private_key_file) {
                anubis_verbose("Using private key: \"%s\"\n", config->private_key_file);
            }
            
            if(config->certificate_file && config->private_key_file &&
               !SSL_CTX_check_private_key(ctx)) {
                anubis_err("Socket[%d] Private key does not match the certificate public key\n", config->index);
                return;
            }//end if
        }
        
        //load ceritificate
        if (config->certificate_file &&
            SSL_CTX_use_certificate_file(ctx, config->certificate_file, SSL_FILETYPE_PEM) <= 0) {
            anubis_ssl_perror("SSL_CTX_use_certificate_file()");
            if(config->role == ANUBIS_ROLE_SERVER)
                return;
        }//end if
        else if(config->certificate_file) {
            anubis_verbose("Using certificate: \"%s\"\n", config->certificate_file);
        }
        
        //load private key
        if (config->private_key_file &&
            SSL_CTX_use_PrivateKey_file(ctx, config->private_key_file, SSL_FILETYPE_PEM) <= 0) {
            anubis_ssl_perror("SSL_CTX_use_PrivateKey_file()");
            if(config->role == ANUBIS_ROLE_SERVER)
                return;
        }//end if
        else if(config->private_key_file) {
            anubis_verbose("Using private key: \"%s\"\n", config->private_key_file);
        }
        
        if(config->certificate_file && config->private_key_file &&
           !SSL_CTX_check_private_key(ctx)) {
            anubis_err("Socket[%d] Private key does not match the certificate public key\n", config->index);
            if(config->role == ANUBIS_ROLE_SERVER)
                return;
        }//end if
    }
    
    
    //open socket
    sd = socket(AF_INET, config->type, 0);
    //set socket option
    sd = anubis_set_socket_option(config, sd);
    if(sd == -1)
        return;
    
    if(config->role == ANUBIS_ROLE_SERVER) {
        //listen
        if(listen(sd, config->max_connection) == -1) {
            anubis_perror("listen()");
            return;
        }//end if
    }
    else if(config->role == ANUBIS_ROLE_CLIENT) {
        //connect
        memset(&server_sin, 0, sizeof(server_sin));
        server_sin.sin_family = AF_INET;
        server_sin.sin_addr.s_addr = config->dst_ip;
        server_sin.sin_port = htons(config->dst_port);
#if !(__linux) && !(WIN32)
        server_sin.sin_len = sizeof(struct sockaddr_in);
#endif
        
        if(connect(sd, (struct sockaddr *)&server_sin, sizeof(server_sin)) == -1) {
            anubis_perror("connect()");
            return;
        }//end if
    }//end if
    
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
        
        //set outter timeout
#ifdef SO_SNDTIMEO
        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = config->send_timeout / 1000;
        timeout.tv_usec = config->send_timeout % 1000;
        if(config->send_timeout) {
            anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
            if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
                anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
                close(sd);
                return;
            }
        }//end if
#endif
        
#ifdef SO_RCVTIMEO
        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = config->recv_timeout / 1000;
        timeout.tv_usec = config->recv_timeout % 1000;
        if(config->recv_timeout) {
            anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
            if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
                close(sd);
                return;
            }
        }//end if
#endif
        
        if(config->role == ANUBIS_ROLE_SERVER) {
            
            int client_sd;
            struct sockaddr_in client_sin = {0};
            socklen_t len = sizeof(client_sin);
            anubis_out("Waiting client...\n");
            if((client_sd = accept(sd, (struct sockaddr *)&client_sin, &len)) == -1) {
                anubis_perror("accept()");
                continue;
            }//end if
            else {
                if(config->asynchronous) {
                    pid_t pid = fork();
                    if(pid == 0) {
                        anubis_handle_tcp_socket(config, outter_amount, client_sd, &client_sin, ctx);
                        exit(0);
                    }//end if
                    else if(pid == -1) {
                        anubis_perror("fork()");
                        continue;
                    }//end else
                }//end if
                else {
                    anubis_handle_tcp_socket(config, outter_amount, client_sd, &client_sin, ctx);
                }//end else
            }//end else
        }//end if server
        else if(config->role == ANUBIS_ROLE_CLIENT) {
            anubis_handle_tcp_socket(config, outter_amount, sd, &server_sin, ctx);
        }//end if client
        
        if(config->interval) {
            anubis_wait_microsecond(config->interval);
        }//end if
    }//end outter loop
    close(sd);
    if(ctx)
        SSL_CTX_free(ctx);
}//end anubis_write_stream

void anubis_write_application(anubis_t *config) {

    if(config->type == SOCK_DGRAM) {
        if(config->role == ANUBIS_ROLE_SERVER)
            anubis_out("Socket[%d] I am a datagram server\n", config->index);
        else if(config->role == ANUBIS_ROLE_CLIENT)
            anubis_out("Socket[%d] I am a datagram client\n", config->index);
        
        anubis_write_datagram(config);
    }//end if udp
    else if(config->type == SOCK_STREAM) {
        if(config->role == ANUBIS_ROLE_SERVER)
            anubis_out("Socket[%d] I am a stream server\n", config->index);
        else if(config->role == ANUBIS_ROLE_CLIENT)
            anubis_out("Socket[%d] I am a stream client\n", config->index);
        
        anubis_write_stream(config);
    }//end if tcp
    
}//end anubis_write_application


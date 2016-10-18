//
//  anubis_writer.c
//  Anubis
//
//  Created by TUTU on 2016/4/1.
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



#ifdef WIN32
bool anubis_init_winsock(void) {
    WSADATA	WSAData = { 0 };
    if (WSAStartup(WSA_VERSION, &WSAData) != 0)
    {
        // Tell the user that we could not find a usable WinSock DLL.
        if (LOBYTE(WSAData.wVersion) != LOBYTE(WSA_VERSION) ||
            HIBYTE(WSAData.wVersion) != HIBYTE(WSA_VERSION))
            anubis_err("WSAStartup(): Incorrect winsock version\n");
        
        WSACleanup();
        return false;
    }
    return true;
}//end initWinsock
#endif

u_int16_t anubis_checksum(u_int16_t *data, int len) {
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
}//end anubis_checksum

void anubis_build_headers(libnet_t *handle, anubis_packet_t *packet) {
    
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



/**
 http://stackoverflow.com/questions/20616029/os-x-equivalent-of-so-bindtodevice
 */
int anubis_bind_to_device(int sock, int family, const char *devicename, u_int16_t port) {

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
	if (!found) {
		pAdapterFound.sin_family = family; //always bind to chosen address type
#if !(__linux) && !(__CYGWIN__)
		pAdapterFound.sin_len = sizeof(struct sockaddr_in);
#endif
	}//end if not found
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
}//end anubis_bind_to_device

int anubis_set_socket_option(anubis_t *config, int sd) {
    
#ifdef __svr4__
	int n = 1;
	void *nptr = &n;
#elif __CYGWIN__
	int n = 1;
	int *nptr = &n;
#else
	int n = 1;
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
    /*Windows(cygwin) application socket and tcp can't not broadcast*/
#ifdef __CYGWIN__
	if (!(config->socket_type == anubis_application_socket &&
          config->protocol == IPPROTO_TCP)) {
#endif
		anubis_verbose("Setting socket option: \"SO_BROADCAST\"\n");
		if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, nptr, sizeof(n)) == -1) {
			anubis_perror("setsockopt(): set SO_BROADCAST failed");
			close(sd);
			return -1;
		}//end if
#ifdef __CYGWIN__
	}
#endif
#endif  /*  SO_BROADCAST  */
    
    /*bind to device*/
    /*Windows(cygwin) transport socket and tcp can't not bind*/
#ifdef __CYGWIN__
    if(!(config->socket_type == anubis_transport_socket &&
         config->protocol == IPPROTO_TCP)) {
#endif
    if(anubis_bind_to_device(sd, AF_INET,
                             config->device,
                             config->socket_type == anubis_transport_socket ? 0 : config->src_port) == -1) {
        close(sd);
        return -1;
    }//end if
#ifdef __CYGWIN__
    }
#endif
    
#ifdef SO_REUSEADDR
	if ((config->socket_type != anubis_application_socket) &&
	    (config->type == SOCK_DGRAM || config->type == SOCK_STREAM)) {
        n = 1;
        anubis_verbose("Setting socket option: \"SO_REUSEADDR\"\n");
        if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (const void*) nptr, (socklen_t) sizeof(n)) == -1) {
            anubis_perror("setsockopt(): set SO_REUSEADDR failed");
            close(sd);
            return -1;
        }
#endif
	    
#ifdef SO_REUSEPORT
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

int anubis_build_fake_header(anubis_t *config,
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


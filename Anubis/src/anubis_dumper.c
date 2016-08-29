//
//  anubis_dumper.c
//  Anubis
//
//  Created by TUTU on 2016/4/2.
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

static void anubis_dump_tcp(u_int32_t *dump_length, u_int32_t total_length, struct libnet_tcp_hdr *tcp);
static void anubis_dump_udp(u_int32_t *dump_length, u_int32_t total_length, struct libnet_udp_hdr *udp);
static void anubis_dump_ip(u_int32_t *dump_length, u_int32_t total_length, struct libnet_ipv4_hdr *ip, int from_icmp);
static void anubis_dump_icmp(u_int32_t *dump_length, u_int32_t total_length, anubis_icmp_t *icmp);
static void anubis_dump_arp(u_int32_t *dump_length, u_int32_t total_length, const u_int8_t *content);
static void anubis_dump_payload(u_int32_t length, u_int32_t total_length, const u_int8_t *content);
static void anubis_dump_tcp_mini(u_int32_t *dump_length, u_int32_t total_length, struct libnet_tcp_hdr *tcp);

static void anubis_dump_payload(u_int32_t dump_length, u_int32_t total_length, const u_int8_t *content) {
    
    fprintf(out_stream, "Payload: \n");
    //hex dump
    fprintf(out_stream, "+--------------------------------------------------------------+\n");
    fprintf(out_stream, "%-22s", "| Payload(Hexadecimal): ");
    int i = 0;
    for(i = 0 ; i < dump_length; i++) {
        if(i && i % 8 == 0)
            fprintf(out_stream, "|\n|%-23s", "");
        //i == ((len - dump_len)/8-1)*8
        
        if(content[i] == 0x00)
            fprintf(out_stream, "0x00");
        else
            fprintf(out_stream, "%#04x", content[i]);
        
        if(i + 1 != dump_length && !(i && (i+1) % 8 == 0))
            fprintf(out_stream, " ");
    }//end for
    
    //padding
    i = 8-abs(i%8) == 8 ? 0 : (8-abs(i%8))*5;
    while(i--)
        fprintf(out_stream, " ");
    fprintf(out_stream, "|\n");
    
    //ascii dump
    fprintf(out_stream, "+--------------------------------------------------------------+\n");
    fprintf(out_stream, "%-22s", "| Payload(ASCII): ");
    for(i = 0 ; i < dump_length; i++) {
        if(i && i % 32 == 0)
            fprintf(out_stream, "|\n|%-20s", "");
        if(i && i % 16 == 0)
            fprintf(out_stream, " ");
        
        if(isgraph(content[i]))
            fprintf(out_stream, "%c", content[i]);
        else
            fprintf(out_stream, ".");
        
    }//end for
    
    //padding
    i = 32-abs(i%32) == 32 ? 0 : 32-abs(i%32)+1;
    if(i != 0 && i <= 16) i-=1;
    while(i--)
        fprintf(out_stream, " ");
    fprintf(out_stream, "|\n");
    
    //length
    fprintf(out_stream, "+--------------------------------------+---------------+\n");
    fprintf(out_stream, "%-25s%8d byte%s", "| Payload length: ",
            dump_length, dump_length > 0 ? "s|\n" : " |\n");
    fprintf(out_stream, "+--------------------------------------+\n");
    fprintf(out_stream, "Payload(Raw):\n%*s", dump_length, content);
}//end anubis_dump_payload

static void anubis_dump_icmp(u_int32_t *dump_length, u_int32_t total_length, anubis_icmp_t *icmp) {
    
    //copy header
    u_int8_t type = icmp->icmp_type;
    u_int8_t code = icmp->icmp_code;
    u_int8_t checksum = ntohs(icmp->icmp_cksum);
    
    static char *type_name[] = {
        "Echo Reply",               /* Type  0 */
        "Undefine",                 /* Type  1 */
        "Undefine",                 /* Type  2 */
        "Destination Unreachable",  /* Type  3 */
        "Source Quench",            /* Type  4 */
        "Redirect (change route)",  /* Type  5 */
        "Undefine",                 /* Type  6 */
        "Undefine",                 /* Type  7 */
        "Echo Request",             /* Type  8 */
        "Undefine",                 /* Type  9 */
        "Undefine",                 /* Type 10 */
        "Time Exceeded",            /* Type 11 */
        "Parameter Problem",        /* Type 12 */
        "Timestamp Request",        /* Type 13 */
        "Timestamp Reply",          /* Type 14 */
        "Information Request",      /* Type 15 */
        "Information Reply",        /* Type 16 */
        "Address Mask Request",     /* Type 17 */
        "Address Mask Reply",       /* Type 18 */
        "Unknown"                   /* Type 19 */
    }; //icmp type
#define ICMP_TYPE_NAME_MAX (sizeof type_name / sizeof type_name[0])
    
    if (type < 0 || ICMP_TYPE_NAME_MAX <= type)
        type = ICMP_TYPE_NAME_MAX - 1;
    
    fprintf(out_stream, "Protocol: ICMP (%s)\n", type_name[type]);
    
    fprintf(out_stream, "+------------+------------+-------------------------+\n");
    fprintf(out_stream, "| Type:   %3u| Code:   %3u| Checksum:          %5u|\n", type, code, checksum);
    fprintf(out_stream, "+------------+------------+-------------------------+\n");
    
    if (type == ICMP_ECHOREPLY || type == ICMP_ECHO) {
        fprintf(out_stream, "| Identification:    %5u| Sequence Number:   %5u|\n", ntohs(icmp->icmp_id), ntohs(icmp->icmp_seq));
        fprintf(out_stream, "+-------------------------+-------------------------+\n");
        
        *dump_length += LIBNET_ICMPV4_ECHO_H;
    }//end if
    else if (type == ICMP_UNREACH) {
        if (code == ICMP_UNREACH_NEEDFRAG) {
            fprintf(out_stream, "| void:              %5u| Next MTU:          %5u|\n", ntohs(icmp->icmp_pmvoid), ntohs(icmp->icmp_nextmtu));
            fprintf(out_stream, "+-------------------------+-------------------------+\n");
        }//end if
        else {
            fprintf(out_stream, "| Unused:                                 %10lu|\n", (unsigned long) ntohl(icmp->icmp_void));
            fprintf(out_stream, "+-------------------------+-------------------------+\n");
        }//end else
        
        *dump_length += LIBNET_ICMPV4_UNREACH_H;
    }//end if
    else if (type == ICMP_REDIRECT) {
        fprintf(out_stream, "| Router IP Address:                 %15s|\n", anubis_ip_ntoa(icmp->icmp_gwaddr.s_addr));
        fprintf(out_stream, "+---------------------------------------------------+\n");
        
        *dump_length += LIBNET_ICMPV4_REDIRECT_H;
    }//end if
    else if (type == ICMP_TIMXCEED) {
        fprintf(out_stream, "| Unused:                                 %10lu|\n", (unsigned long)ntohl(icmp->icmp_void));
        fprintf(out_stream, "+---------------------------------------------------+\n");
        
        *dump_length += LIBNET_ICMPV4_TIMXCEED_H;
    }//end else
    
    if(*dump_length >= total_length)
        return;
    
    //if the icmp packet carry ip header
    if (type == ICMP_UNREACH || type == ICMP_REDIRECT || type == ICMP_TIMXCEED) {
        struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)icmp->icmp_data;
        char *p = (char *)ip + (ip->ip_hl << 2);
        anubis_dump_ip(dump_length, total_length, ip, 1);
        
        switch (ip->ip_p) {
            case IPPROTO_TCP:
                if(type == ICMP_REDIRECT) {
                    anubis_dump_tcp_mini(dump_length, total_length, (struct libnet_tcp_hdr *)p);
                }//end if
                else {
                    anubis_dump_tcp(dump_length, total_length, (struct libnet_tcp_hdr *)p);
                }//end else
                break;
        }//end switch
    }//end if
}//end anubis_dump_icmp

static void anubis_dump_tcp_mini(u_int32_t *dump_length, u_int32_t total_length, struct libnet_tcp_hdr *tcp) {
    
    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    u_int32_t sequence = ntohl(tcp->th_seq);
    *dump_length += 8;
    
    //print
    printf("Protocol: TCP\n");
    printf("+-------------------------+-------------------------+\n");
    printf("| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    printf("+-------------------------+-------------------------+\n");
    printf("| Sequence Number:                        %10u|\n", sequence);
    printf("+---------------------------------------------------+\n");
}//end anubis_dump_tcp_mini

static void anubis_dump_tcp(u_int32_t *dump_length, u_int32_t total_length, struct libnet_tcp_hdr *tcp) {
    
    //copy header
    u_int16_t source_port = ntohs(tcp->th_sport);
    u_int16_t destination_port = ntohs(tcp->th_dport);
    u_int32_t sequence = ntohl(tcp->th_seq);
    u_int32_t ack = ntohl(tcp->th_ack);
    u_int8_t header_len = tcp->th_off << 2;
    u_int8_t flags = tcp->th_flags;
    u_int16_t window = ntohs(tcp->th_win);
    u_int16_t checksum = ntohs(tcp->th_sum);
    u_int16_t urgent = ntohs(tcp->th_urp);
    *dump_length += header_len;
    
    //print
    fprintf(out_stream, "Protocol: TCP\n");
    fprintf(out_stream, "+-------------------------+-------------------------+\n");
    fprintf(out_stream, "| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    fprintf(out_stream, "+-------------------------+-------------------------+\n");
    fprintf(out_stream, "| Sequence Number:                        %10u|\n", sequence);
    fprintf(out_stream, "+---------------------------------------------------+\n");
    fprintf(out_stream, "| Acknowledgement Number:                 %10u|\n", ack);
    fprintf(out_stream, "+------+-------+----------+-------------------------+\n");
    fprintf(out_stream, "| HL:%2u|  RSV  |F:%8s| Window Size:       %5u|\n", header_len, anubis_tcp_ftoa(flags), window);
    fprintf(out_stream, "+------+-------+----------+-------------------------+\n");
    fprintf(out_stream, "| Checksum:          %5u| Urgent Pointer:    %5u|\n", checksum, urgent);
    fprintf(out_stream, "+-------------------------+-------------------------+\n");
    
}//end anubis_dump_tcp

static void anubis_dump_udp(u_int32_t *dump_length, u_int32_t total_length, struct libnet_udp_hdr *udp) {
    
    u_int16_t source_port = ntohs(udp->uh_sport);
    u_int16_t destination_port = ntohs(udp->uh_dport);
    u_int16_t len = ntohs(udp->uh_ulen);
    u_int16_t checksum = ntohs(udp->uh_sum);
    *dump_length += LIBNET_UDP_H;
    
    //print
    fprintf(out_stream, "Protocol: UDP\n");
    fprintf(out_stream, "+-------------------------+-------------------------+\n");
    fprintf(out_stream, "| Source Port:       %5u| Destination Port:  %5u|\n", source_port, destination_port);
    fprintf(out_stream, "+-------------------------+-------------------------+\n");
    fprintf(out_stream, "| Length:            %5u| Checksum:          %5u|\n", len, checksum);
    fprintf(out_stream, "+-------------------------+-------------------------+\n");
    
}//end anubis_dump_udp

static void anubis_dump_ip(u_int32_t *dump_length, u_int32_t total_length, struct libnet_ipv4_hdr *ip, int from_icmp) {
    
    //copy header
    u_int version = ip->ip_v;
    u_int header_len = ip->ip_hl << 2;
    u_int8_t tos = ip->ip_tos;
    u_int16_t total_len = ntohs(ip->ip_len);
    u_int16_t id = ntohs(ip->ip_id);
    u_int16_t offset = ntohs(ip->ip_off);
    u_int8_t ttl = ip->ip_ttl;
    u_int8_t protocol = ip->ip_p;
    u_int16_t checksum = ntohs(ip->ip_sum);
    *dump_length += header_len;
    
    //print
    fprintf(out_stream, "Protocol: IP\n");
    fprintf(out_stream, "+-----+------+------------+-------------------------+\n");
    fprintf(out_stream, "| IV:%1u| HL:%2u| T: %8s| Total Length: %10u|\n",
           version, header_len, anubis_ip_ttoa(tos), total_len);
    fprintf(out_stream, "+-----+------+------------+-------+-----------------+\n");
    fprintf(out_stream, "| Identifier:        %5u| FF:%3s| FO:        %5u|\n",
           id, anubis_ip_ftoa(offset), offset & IP_OFFMASK);
    fprintf(out_stream, "+------------+------------+-------+-----------------+\n");
    fprintf(out_stream, "| TTL:    %3u| Pro:    %3u| Header Checksum:   %5u|\n",
           ttl, protocol, checksum);
    fprintf(out_stream, "+------------+------------+-------------------------+\n");
    fprintf(out_stream, "| Source IP Address:                 %15s|\n",  anubis_ip_ntoa(*(in_addr_t *)&ip->ip_src));
    fprintf(out_stream, "+---------------------------------------------------+\n");
    fprintf(out_stream, "| Destination IP Address:            %15s|\n", anubis_ip_ntoa(*(in_addr_t *)&ip->ip_dst));
    fprintf(out_stream, "+---------------------------------------------------+\n");
    
    char *p = (char *)ip + (ip->ip_hl << 2);
    switch (protocol) {
        case IPPROTO_UDP:
            anubis_dump_udp(dump_length, total_length, (struct libnet_udp_hdr *)p);
            break;
            
        case IPPROTO_TCP:
            if(!from_icmp)
                anubis_dump_tcp(dump_length, total_length, (struct libnet_tcp_hdr *)p);
            break;
            
        case IPPROTO_ICMP:
            anubis_dump_icmp(dump_length, total_length, (anubis_icmp_t *)p);
            break;
            
        default:
            fprintf(out_stream, "Next protocol: %d\n", protocol);
            break;
    }//end switch
}//end dump_ip

static void anubis_dump_arp(u_int32_t *dump_length, u_int32_t total_length, const u_int8_t *content) {
    anubis_ether_arp_t *arp = (anubis_ether_arp_t *)(content);
    u_int16_t hardware_type = ntohs(arp->ea_hdr.ar_hrd);
    u_int16_t protocol_type = ntohs(arp->ea_hdr.ar_pro);
    u_int8_t hardware_len = arp->ea_hdr.ar_hln;
    u_int8_t protocol_len = arp->ea_hdr.ar_pln;
    u_int16_t operation = ntohs(arp->ea_hdr.ar_op);
    *dump_length += LIBNET_ARP_ETH_IP_H;
    
    static char *arp_op_name[] = {
        "Undefine",
        "(ARP Request)",
        "(ARP Reply)",
        "(RARP Request)",
        "(RARP Reply)"
    }; //arp option type
    
    if(operation < 0 || sizeof(arp_op_name)/sizeof(arp_op_name[0]) < operation)
        operation = 0;
    
    fprintf(out_stream, "Protocol: ARP/RARP\n");
    fprintf(out_stream, "+-------------------------+-------------------------+\n");
    fprintf(out_stream, "| Hard Type: %2u%-11s| Protocol: 0x%04x%-8s|\n",
           hardware_type,
           (hardware_type == ARPHRD_ETHER) ? "(Ethernet)" : "(Not Ether)",
           protocol_type,
           (protocol_type == ETHERTYPE_IP) ? "(IP)" : "(Not IP)");
    fprintf(out_stream, "+------------+------------+-------------------------+\n");
    fprintf(out_stream, "| HardLen:%3u| Addr Len:%2u| OP: %4d%16s|\n",
           hardware_len, protocol_len, operation, arp_op_name[operation]);
    fprintf(out_stream, "+------------+------------+-------------------------+-------------------------+\n");
    fprintf(out_stream, "| Source MAC Address:                                        %17s|\n", anubis_mac_ntoa(arp->arp_sha));
    fprintf(out_stream, "+---------------------------------------------------+-------------------------+\n");
    fprintf(out_stream, "| Source IP Address:                 %15s|\n", anubis_ip_ntoa(*(in_addr_t *)arp->arp_spa));
    fprintf(out_stream, "+---------------------------------------------------+-------------------------+\n");
    fprintf(out_stream, "| Destination MAC Address:                                   %17s|\n", anubis_mac_ntoa(arp->arp_tha));
    fprintf(out_stream, "+---------------------------------------------------+-------------------------+\n");
    fprintf(out_stream, "| Destination IP Address:            %15s|\n", anubis_ip_ntoa(*(in_addr_t *)arp->arp_tpa));
    fprintf(out_stream, "+---------------------------------------------------+\n");
    
}//end anubis_dump_arp

static void anubis_dump_wol(u_int32_t *dump_length, u_int32_t total_length, anubis_wol_hdr *wol) {
    
    *dump_length += ANUBIS_WOL_H;
    
    fprintf(out_stream, "Protocol: Wake-On-LAN\n");
    fprintf(out_stream, "+-------------------------+-------------------------+-------------------------+\n");
    fprintf(out_stream, "| Sync Stream:                                               %17s|\n", anubis_mac_ntoa(wol->sync_stream));
    fprintf(out_stream, "+-------------------------+-------------------------+-------------------------+\n");
    
    for(int i = 0 ; i < sizeof(wol->mac_address)/sizeof(wol->mac_address[0]) ; i++) {
        fprintf(out_stream, "| MAC Address:                                               %17s|\n", anubis_mac_ntoa(wol->mac_address[i]));
        fprintf(out_stream, "+-------------------------+-------------------------+-------------------------+\n");
    }//end for
    
    fprintf(out_stream, "| Password:                                                  %17s|\n", anubis_mac_ntoa(wol->password));
    fprintf(out_stream, "+-------------------------+-------------------------+-------------------------+\n");
    
}//end anubis_dump_wol

void anubis_dump_ethernet(u_int32_t *dump_length, u_int32_t total_length, const u_int8_t *content) {
    struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr *)content;
    char dst_mac_addr[MAC_ADDRSTRLEN] = {0};
    char src_mac_addr[MAC_ADDRSTRLEN] = {0};
    u_int16_t type;
    *dump_length += LIBNET_ETH_H;
    
    //copy header
    strlcpy(dst_mac_addr, anubis_mac_ntoa(ethernet->ether_dhost), sizeof(dst_mac_addr));
    strlcpy(src_mac_addr, anubis_mac_ntoa(ethernet->ether_shost), sizeof(src_mac_addr));
    type = ntohs(ethernet->ether_type);
    
    //print
    if(type <= 1500)
        fprintf(out_stream, "IEEE 802.3 Ethernet Frame:\n");
    else
        fprintf(out_stream, "Ethernet Frame:\n");
    
    fprintf(out_stream, "+-------------------------+-------------------------+-------------------------+\n");
    fprintf(out_stream, "| Destination MAC Address:                                   %17s|\n", dst_mac_addr);
    fprintf(out_stream, "+-------------------------+-------------------------+-------------------------+\n");
    fprintf(out_stream, "| Source MAC Address:                                        %17s|\n", src_mac_addr);
    fprintf(out_stream, "+-------------------------+-------------------------+-------------------------+\n");
    if (type < 1500)
        fprintf(out_stream, "| Length:            %5u|\n", type);
    else
        fprintf(out_stream, "| Ethernet Type:    0x%04x|\n", type);
    fprintf(out_stream, "+-------------------------+\n");
    
    switch (type) {
        case ETHERTYPE_ARP:
        case ETHERTYPE_REVARP:
            anubis_dump_arp(dump_length, total_length, content + LIBNET_ETH_H);
            break;
            
        case ETHERTYPE_IP:
            anubis_dump_ip(dump_length, total_length, (struct libnet_ipv4_hdr *)(content + LIBNET_ETH_H), 0);
            break;
            
        case ETHERTYPE_WOL:
            anubis_dump_wol(dump_length, total_length, (anubis_wol_hdr *)(content + LIBNET_ETH_H));
            break;
            /*
        case ETHERTYPE_REVARP:
            fprintf(out_stream, "Next is RARP\n");
            break;
            
        case ETHERTYPE_IPV6:
            fprintf(out_stream, "Next is IPv6\n");
            break;
            */
        default:
            //fprintf(out_stream, "Next protocol: %#06x\n", type);
            break;
    }//end switch
    
}//end anubis_dump_ethernet

void anubis_dump_libnet_content(libnet_t *handle, int transport_layer, int is_application_layer) {
    int c;
    uint32_t len = 0;
    uint8_t *content = NULL;
    uint32_t dump_len = 0;
    
    c = libnet_pblock_coalesce(handle, &content, &len);
    if (c == - 1) {
        anubis_err("libnet_pblock_coalesce(): %s\n", libnet_geterror(handle));
        return;
    }//end if
    
    //libnet_diag_dump_hex(content, len, 0, out_stream);
    //return;
    
    if(!transport_layer) {
        if(handle->injection_type == LIBNET_LINK)
            anubis_dump_ethernet(&dump_len, len, content);
        else if(handle->injection_type == LIBNET_RAW4)
            anubis_dump_ip(&dump_len, len, (struct libnet_ipv4_hdr *)content, 0);
    }//end if
    else {
        struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)content;
        dump_len += ip->ip_hl << 2;
        char *p = (char *)ip + (ip->ip_hl << 2);
        switch (ip->ip_p) {
            case IPPROTO_UDP:
                if(is_application_layer) {
                    dump_len += LIBNET_UDP_H;
                }
                else {
                    anubis_dump_udp(&dump_len, len, (struct libnet_udp_hdr *)p);
                }
                break;
                
            case IPPROTO_TCP:
                if(is_application_layer) {
                    dump_len += ((struct libnet_tcp_hdr *)p)->th_off << 2;
                }
                else {
                    anubis_dump_tcp(&dump_len, len, (struct libnet_tcp_hdr *)p);
                }//end if
                break;
                
            case IPPROTO_ICMP:
                if(is_application_layer) {
                    anubis_err("TUTU: Sorry, I am lazy\n");
                }//end if 
                anubis_dump_icmp(&dump_len, len, (anubis_icmp_t *)p);
                break;
                
            default:
                fprintf(out_stream, "Next protocol: %d\n", ip->ip_p);
                break;
        }//end switch
    }//end else if transport
    
    //remain data
    if(len > dump_len)
        anubis_dump_payload(len - dump_len, len, content + dump_len);
    fprintf(out_stream, "[EOP]\n\n");
    
#ifndef __CYGWIN__
    //free
    if (handle->aligner > 0) {
        content = content - handle->aligner;
    }//end if
    free(content);
#endif
    
    fflush(out_stream);
}//end anubis_dump_libnet_content

void anubis_dump_application(const char *content, u_int32_t length) {
    
    if(length <= 0)
        return;
    anubis_dump_payload(length, length, (const u_int8_t *)content);
    fprintf(out_stream, "[EOP]\n\n");
    
    fflush(out_stream);
}//end anubis_dump_application

void anubis_dump_server_certificate(SSL *ssl) {
    X509 *x509Cert = SSL_get_peer_certificate(ssl);
    char buffer[1024];
    BIO *bio = NULL;
    char *buf = NULL;
    
    if(!x509Cert) {
        anubis_ssl_perror("SSL_get_peer_certificate()");
        return;
    }
    
    bio = BIO_new(BIO_s_mem());
    if(!bio) {
        anubis_ssl_perror("BIO_new()");
        X509_free(x509Cert);
        return;
    }//end if
    
    BIO_reset(bio);
    if(!PEM_write_bio_X509(bio, x509Cert)) {
        anubis_ssl_perror("PEM_write_bio_X509()");
        BIO_free(bio);
        X509_free(x509Cert);
        return;
    }
    BIO_get_mem_data(bio, &buf);
    anubis_out("Server certificate:\n%s", buf);
    // Cert Version
    long version = 0;
    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VERSION)) {
        version = X509_get_version(x509Cert);
        fprintf(out_stream, "Version: %ld\n", version);
    }//end if
    
    // Cert Serial No. - Code adapted from OpenSSL's crypto/asn1/t_x509.c
    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SERIAL)) {
        ASN1_INTEGER *bs;
        long l;
        int i;
        const char *neg;
        bs = X509_get_serialNumber(x509Cert);
        
        if (bs->length <= 4) {
            l = ASN1_INTEGER_get(bs);
            if (l < 0) {
                l= -l;
                neg = "-";
            }
            else
                neg = "";
            
            fprintf(out_stream, "Serial Number: %lu (%#lx)\n", l, l);
        }
        else {
            neg = (bs->type == V_ASN1_NEG_INTEGER)?" (Negative)":"";
            fprintf(out_stream, "Serial Number: %s", neg);
            for (i = 0; i < bs->length; i++) {
                fprintf(out_stream, "%02x%c", bs->data[i], (i+1 == bs->length)?'\n':':');
            }
        }
    }
    
    // Signature Algo...
    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SIGNAME)) {
        i2a_ASN1_OBJECT(bio, x509Cert->cert_info->signature->algorithm);
        BIO_get_mem_data(bio, &buf);
        fprintf(out_stream, "Signature Algorithm:\n%s\n", buf);
    }
    
    // SSL Certificate Issuer...
    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_ISSUER)) {
        X509_NAME_oneline(X509_get_issuer_name(x509Cert), buffer, sizeof(buffer) - 1);
        fprintf(out_stream, "Issuer: %s\n", buffer);
    }
    
    // Validity...
    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VALIDITY)) {
        BIO_reset(bio);
        ASN1_TIME_print(bio, X509_get_notBefore(x509Cert));
        BIO_get_mem_data(bio, &buf);
        fprintf(out_stream, "Not Valid Before: %s\n", buf);
        
        BIO_reset(bio);
        ASN1_TIME_print(bio, X509_get_notAfter(x509Cert));
        BIO_get_mem_data(bio, &buf);
        fprintf(out_stream, "Not Valid After: %s\n", buf);
    }
    
    // SSL Certificate Subject...
    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SUBJECT)) {
        X509_NAME_oneline(X509_get_subject_name(x509Cert), buffer, sizeof(buffer) - 1);
        fprintf(out_stream, "Subject: %s\n", buffer);
    }
    
    // Public Key Algo...
    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_PUBKEY)) {
        BIO_reset(bio);
        i2a_ASN1_OBJECT(bio, x509Cert->cert_info->key->algor->algorithm);
        BIO_get_mem_data(bio, &buf);
        fprintf(out_stream, "Public Key Algorithm: %s\n", buf);
        
        // Public Key...
        EVP_PKEY *publicKey = NULL;
        publicKey = X509_get_pubkey(x509Cert);
        if (publicKey == NULL) {
            anubis_err("Public Key Could not load\n");
        }
        else {
            BIO_reset(bio);
            char *publicKeyType = NULL;
            int publicKeyLength = -1;
            switch (publicKey->type) {
                case EVP_PKEY_RSA:
                    
                    publicKeyType = "RSA";
                    
                    if (publicKey->pkey.rsa) {
                        publicKeyLength = BN_num_bits(publicKey->pkey.rsa->n);
                        RSA_print(bio, publicKey->pkey.rsa, 0);
                        BIO_get_mem_data(bio, &buf);
                    }
                    break;
                case EVP_PKEY_DSA:
                    
                    publicKeyType = "DSA";
                    
                    if (publicKey->pkey.dsa) {
                        DSA_print(bio, publicKey->pkey.dsa, 0);
                        BIO_get_mem_data(bio, &buf);
                    }
                    break;
                case EVP_PKEY_EC:
                    publicKeyType = "EC";
                    
                    if (publicKey->pkey.ec)  {
                        EC_KEY_print(bio, publicKey->pkey.ec, 0);
                        BIO_get_mem_data(bio, &buf);
                    }
                    break;
                default:
                    publicKeyType = "Unknown";
                    break;
            }
            
            EVP_PKEY_free(publicKey);
            fprintf(out_stream, "%d Public Key: ", publicKeyLength);
            if(!strcasecmp(publicKeyType, "RSA")) {
                fprintf(out_stream, "(%d bits)", publicKeyLength);
            }
            fprintf(out_stream, "\n");
            fprintf(out_stream, "%s\n", buf);
        }
    }
    
    // X509 v3...
    if (!(X509_FLAG_COMPAT & X509_FLAG_NO_EXTENSIONS) && sk_X509_EXTENSION_num(x509Cert->cert_info->extensions) > 0) {
        X509_EXTENSION *extension = NULL;
        ASN1_OBJECT *asn1Object = NULL;
        int tempInt2 = 0;
        BIO_reset(bio);
        for (int tempInt = 0; tempInt < sk_X509_EXTENSION_num(x509Cert->cert_info->extensions); tempInt++) {
            // Get Extension...
            extension = sk_X509_EXTENSION_value(x509Cert->cert_info->extensions, tempInt);
            
            asn1Object = X509_EXTENSION_get_object(extension);
            i2a_ASN1_OBJECT(bio, asn1Object);
            tempInt2 = X509_EXTENSION_get_critical(extension);
            BIO_printf(bio, ": %s\n", tempInt2 ? "critical" : "");
            
            // Print Extension value...
            if (!X509V3_EXT_print(bio, extension, X509_FLAG_COMPAT, 8)) {
                M_ASN1_OCTET_STRING_print(bio, extension->value);
            }
            BIO_printf(bio, "\n");
        }//end for
        
        BIO_get_mem_data(bio, &buf);
        fprintf(out_stream, "x509v3 Extensions: %s\n", buf);
    }//end if x509v3
    
    /*
    long verifyError = 0;
    // Verify Certificate...
    verifyError = SSL_get_verify_result(ssl);
    const char *verifyCertificate = "";
    if (verifyError == X509_V_OK)
        verifyCertificate = "Certificate passed verification";
    else
        verifyCertificate = X509_verify_cert_error_string(verifyError);
    fprintf(out_stream, "Validation: %s\n", verifyCertificate);
    */
    
    BIO_free(bio);
    X509_free(x509Cert);
    fflush(out_stream);
}//end anubis_dump_server_certificate
//
//  anubis_defaults.c
//  Anubis
//
//  Created by 聲華 陳 on 2016/3/31.
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

char *anubis_default_device(void) {
    
    pcap_if_t *d = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    static char device[ANUBIS_BUFFER_SIZE] = { 0 };
    
    if (pcap_findalldevs(&d, errbuf) != 0) {
        anubis_err("%s\n", errbuf);
        return NULL;
    }//end if
    
    memset(device, 0, sizeof(device));
    for (pcap_if_t *tmp = d; tmp; tmp = tmp->next) {
        if (
#ifdef PCAP_IF_UP
            (tmp->flags & PCAP_IF_UP) &&
#endif
            !(tmp->flags & PCAP_IF_LOOPBACK)) {
            for (struct pcap_addr *a = tmp->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    strlcpy(device, tmp->name, sizeof(device));
                    break;
                }//end if
            }//end for
        }//end if
        
        if (strlen(device) > 0)
            break;
        
    }//end for
    
    anubis_verbose("Select default device: \"%s\"\n", device);
    
    pcap_freealldevs(d);
    return device;
}//end anubis_default_device

u_int8_t *anubis_default_mac_address(const char *device) {
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *handle = libnet_init(LIBNET_RAW4, device, errbuf);
    static u_int8_t *address = NULL;
    
    if(!handle) {
        anubis_err("%s\n", errbuf);
        return NULL;
    }//end if
    
    struct libnet_ether_addr *src_mac = libnet_get_hwaddr(handle); //it is static
    if(src_mac)
        address = (u_int8_t *)src_mac;
    else
        anubis_err("%s\n", libnet_geterror(handle));
    
    libnet_destroy(handle);
    return address;
}//end anubis_default_mac_address

struct libnet_ethernet_hdr anubis_default_ethernet_header(const char *device) {
    struct libnet_ethernet_hdr ethernet_hdr = {0};
    
    memset(&ethernet_hdr, 0, sizeof(ethernet_hdr));
    
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *handle = libnet_init(LIBNET_RAW4, device, errbuf);
    if(!handle) {
        anubis_err("%s\n", errbuf);
        return ethernet_hdr;
    }//end if
    
    struct libnet_ether_addr *src_mac = libnet_get_hwaddr(handle);
    if(src_mac)
        memmove(ethernet_hdr.ether_shost, src_mac, sizeof(ethernet_hdr.ether_shost));
    else
        anubis_err("%s\n", libnet_geterror(handle));
    
    libnet_destroy(handle);
    return ethernet_hdr;
}//end anubis_default_ethernet_header

anubis_ether_arp_t anubis_default_arp_header(void) {
    anubis_ether_arp_t arp_hdr = {0};
    
    arp_hdr.arp_hrd = ARPHRD_ETHER;
    arp_hdr.arp_pro = ETHERTYPE_IP;
    arp_hdr.arp_hln = ETHER_ADDR_LEN;
    arp_hdr.arp_pln = 4;
    
    return arp_hdr;
}//end anubis_default_arp_header

anubis_wol_hdr anubis_default_wol_header(void) {
    anubis_wol_hdr wol = {0};
    
    memmove(wol.sync_stream, anubis_mac_aton("ff:ff:ff:ff:ff:ff"), sizeof(wol.sync_stream));
    memmove(wol.password, anubis_mac_aton("00:00:00:00:00:00"), sizeof(wol.password));
    
    return wol;
}//end anubis_default_wol_header

struct libnet_ipv4_hdr anubis_default_ip_header(const char *device) {
    struct libnet_ipv4_hdr ip;
    char errbuf[LIBNET_ERRBUF_SIZE];
    int ttl;
    
    memset(&ip, 0, sizeof(ip));
    
    ip.ip_v = IPVERSION;
    ip.ip_hl = sizeof(ip) >> 2;
    
    anubis_srand();
    ip.ip_id = random();
    
#if 0
    int mib[4];
    size_t sz;
    mib[0] = CTL_NET;
    mib[1] = PF_INET;
    mib[2] = IPPROTO_IP;
    mib[3] = IPCTL_DEFTTL;
    sz = sizeof(ttl);
    if (sysctl(mib, 4, &ttl, &sz, NULL, 0) == -1) {
        anubis_perror("sysctl()");
        return ip;
    }//end if
#else
    ttl = 64;
#endif
    
    ip.ip_ttl = ttl;
    
    libnet_t *handle = libnet_init(LIBNET_NONE, device, errbuf);
    if(!handle) {
        anubis_err("%s\n", errbuf);
        return ip;
    }//end if
    ip.ip_src.s_addr = libnet_get_ipaddr4(handle);
    
    libnet_destroy(handle);
    
    return ip;
}//end anubis_default_ip_header

anubis_options_t anubis_default_ip_options(void) {
    anubis_options_t options = {0};
    
    memset(&options, 0, sizeof(options));
    
    return options;
}//end anubis_default_ip_options

struct libnet_udp_hdr anubis_default_udp_header(void) {
    struct libnet_udp_hdr udp = {0};
    
    memset(&udp, 0, sizeof(udp));
    
    return udp;
}//end anubis_default_udp_header

struct libnet_tcp_hdr anubis_default_tcp_header(void) {
    struct libnet_tcp_hdr tcp = {0};
    
    memset(&tcp, 0, sizeof(tcp));
    
    tcp.th_off = LIBNET_TCP_H >> 2;
    
    return tcp;
}//end anubis_default_tcp_header

anubis_options_t anubis_default_tcp_options(void) {
    anubis_options_t options = {0};
    
    memset(&options, 0, sizeof(options));
    
    return options;
}//end anubis_default_tcp_options

anubis_icmp_t anubis_default_icmp_header(void) {
    anubis_icmp_t icmp = {0};
    
    memset(&icmp, 0, sizeof(icmp));
    
    return icmp;
}//end anubis_default_icmp_echo_header

anubis_packet_raw_data_t anubis_default_rip_header(void) {
    anubis_packet_raw_data_t rip = {0};
    
    memset(&rip, 0, sizeof(rip));
    
    return rip;
}//end anubis_default_rip_header

 //end anubis_default_device

anubis_message_hdr anubis_default_ssdp_header(void) {
    anubis_message_hdr ssdp_hdr = {0};
    
    memset(&ssdp_hdr, 0, sizeof(ssdp_hdr));
    ssdp_hdr.version = "HTTP/1.1";
    
    return ssdp_hdr;
}//end anubis_default_ssdp_header

anubis_message_hdr anubis_default_http_header(void) {
    anubis_message_hdr http_hdr = {0};
    
    memset(&http_hdr, 0, sizeof(http_hdr));
    http_hdr.version = "HTTP/1.1";
    
    return http_hdr;
}//end anubis_default_ssdp_header

struct libnet_dhcpv4_hdr anubis_default_dhcp_header(const char *device) {
    
    struct libnet_dhcpv4_hdr dhcp_hdr = {0};
    dhcp_hdr.dhcp_htype = 1;
    dhcp_hdr.dhcp_hlen = ETHER_ADDR_LEN;
    
    anubis_srand();
    dhcp_hdr.dhcp_xid = (u_int32_t)random();
    dhcp_hdr.dhcp_magic = DHCP_MAGIC;
    
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *handle = libnet_init(LIBNET_RAW4, device, errbuf);
    if(!handle) {
        anubis_err("%s\n", errbuf);
        return dhcp_hdr;
    }//end if
    
    struct libnet_ether_addr *my_mac = libnet_get_hwaddr(handle);
    if(my_mac) {
        memmove(dhcp_hdr.dhcp_chaddr, my_mac, sizeof(dhcp_hdr.dhcp_chaddr));
    }
    else {
        anubis_err("%s\n", libnet_geterror(handle));
    }
    
    libnet_destroy(handle);
    return dhcp_hdr;
}//end anubis_default_dhcp_header

anubis_options_t anubis_default_dhcp_options(void) {
    anubis_options_t options = {0};
    
    memset(&options, 0, sizeof(options));
    
    return options;
}//end anubis_default_ip_options
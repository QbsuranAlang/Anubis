//
//  anubis_defaults.c
//  Anubis
//
//  Created by TUTU on 2016/3/31.
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

char *anubis_default_device(void) {
    
    pcap_if_t *d = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
    static char device[ANUBIS_BUFFER_SIZE][ANUBIS_BUFFER_SIZE] = { 0 };
    static int which = -1;
    
    which = (which + 1 == ANUBIS_BUFFER_SIZE ? 0 : which + 1);
    
    memset(device[which], 0, sizeof(device[which]));
    
    if (pcap_findalldevs(&d, errbuf) != 0) {
        anubis_err("%s\n", errbuf);
        return NULL;
    }//end if
    
    memset(device[which], 0, sizeof(device[which]));
    for (pcap_if_t *tmp = d; tmp; tmp = tmp->next) {
        if (
#ifdef PCAP_IF_UP
            (tmp->flags & PCAP_IF_UP) &&
#endif
            !(tmp->flags & PCAP_IF_LOOPBACK)) {
            for (struct pcap_addr *a = tmp->addresses; a; a = a->next) {
                if (a->addr && a->addr->sa_family == AF_INET) {
                    strlcpy(device[which], tmp->name, sizeof(device[which]));
                    break;
                }//end if
            }//end for
        }//end if
        
        if (strlen(device[which]) > 0)
            break;
        
    }//end for
    
	pcap_freealldevs(d);
	
	char *tmp = NULL;
#ifndef __CYGWIN__
	tmp = device[which];
    anubis_verbose("Select default device: \"%s\"\n", device[which]);
#else
	if (!(tmp = strstr(device[which], "{")))
		tmp = device[which];
	anubis_verbose("Select default device: \"%s\"\n", tmp);
#endif
    return tmp;
}//end anubis_default_device

u_int8_t *anubis_default_mac_address(const char *device) {
    char errbuf[LIBNET_ERRBUF_SIZE];
	libnet_t *handle = NULL;
#ifdef __CYGWIN__
	char device2[ANUBIS_BUFFER_SIZE] = {0};
	snprintf(device2, sizeof(device2), "\\Device\\NPF_%s", device);
	handle = anubis_libnet_init(LIBNET_RAW4, device2, errbuf);
#else
	handle = anubis_libnet_init(LIBNET_RAW4, device, errbuf);
#endif
    static u_int8_t *address = NULL;
    
    if(!handle) {
        anubis_err("%s\n", errbuf);
        return NULL;
    }//end if
    
    struct libnet_ether_addr *my_mac = libnet_get_hwaddr(handle); //it is static
    if(my_mac)
        address = (u_int8_t *)my_mac;
    else
        anubis_err("%s\n", libnet_geterror(handle));
    
    libnet_destroy(handle);
    return address;
}//end anubis_default_mac_address

in_addr_t anubis_default_ip_address(const char *device) {
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *handle = NULL;
#ifdef __CYGWIN__
    char device2[ANUBIS_BUFFER_SIZE] = {0};
    snprintf(device2, sizeof(device2), "\\Device\\NPF_%s", device);
    handle = anubis_libnet_init(LIBNET_RAW4, device2, errbuf);
#else
    handle = anubis_libnet_init(LIBNET_RAW4, device, errbuf);
#endif
    
    if(!handle) {
        anubis_err("%s\n", errbuf);
        return 0;
    }//end if
    
    in_addr_t my_ip = libnet_get_ipaddr4(handle);
    if(my_ip == -1) {
        anubis_err("%s\n", libnet_geterror(handle));
        my_ip = 0;
    }//end if
    
    libnet_destroy(handle);
    return my_ip;
}//end anubis_default_ip_address

static int route_default_route_callback(const struct route_entry *entry, void *arg) {
    struct route_entry *route = (struct route_entry *)arg;
    struct sockaddr_in sock = {0};
    
    addr_ntos(&entry->route_dst, (struct sockaddr *)&sock);
    
    if(sock.sin_addr.s_addr == 0) {
        memmove(&route->route_gw, &entry->route_gw, sizeof(route->route_gw));
        return 1;
    }//end if
    
    return 0;
}//end route_default_route_callback

in_addr_t anubis_default_route(void) {
    route_t *handle = route_open();
    struct route_entry route_entry = {0};
    in_addr_t addr = 0;
    
    if(!handle) {
        anubis_perror("route_open()");
        return addr;
    }//end if
    
    int ret = route_loop(handle, route_default_route_callback, (void *)&route_entry);
    
    if(ret == 1) {
        struct sockaddr_in sa = {0};
        addr_ntos(&route_entry.route_gw, (struct sockaddr *)&sa);
        addr = sa.sin_addr.s_addr;
        anubis_verbose("Default route: %s\n", anubis_ip_ntoa(addr));
    }//end if
    else {
        anubis_err("anubis_default_route(): Default gateway is not found\n");
    }//end else
    
    route_close(handle);
    return addr;
}//end anubis_default_route

struct libnet_ethernet_hdr anubis_default_ethernet_header(const char *device) {
    struct libnet_ethernet_hdr ethernet_hdr = {0};
    
    memset(&ethernet_hdr, 0, sizeof(ethernet_hdr));
    
	char errbuf[LIBNET_ERRBUF_SIZE] = {0};
	libnet_t *handle = NULL;
#ifdef __CYGWIN__
	char device2[ANUBIS_BUFFER_SIZE] = {0};
	snprintf(device2, sizeof(device2), "\\Device\\NPF_%s", device);
	handle = anubis_libnet_init(LIBNET_RAW4, device2, errbuf);
#else
	handle = anubis_libnet_init(LIBNET_RAW4, device, errbuf);
#endif
	
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
    
	libnet_t *handle = NULL;
#ifdef __CYGWIN__
	char device2[ANUBIS_BUFFER_SIZE] = {0};
	snprintf(device2, sizeof(device2), "\\Device\\NPF_%s", device);
	handle = anubis_libnet_init(LIBNET_RAW4, device2, errbuf);
#else
	handle = anubis_libnet_init(LIBNET_RAW4, device, errbuf);
#endif
	
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
	libnet_t *handle = NULL;
#ifdef __CYGWIN__
	char device2[ANUBIS_BUFFER_SIZE] = {0};
	snprintf(device2, sizeof(device2), "\\Device\\NPF_%s", device);
	handle = anubis_libnet_init(LIBNET_RAW4, device2, errbuf);
#else
	handle = anubis_libnet_init(LIBNET_RAW4, device, errbuf);
#endif
	
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

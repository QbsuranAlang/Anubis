//
//  anubis_defaults.h
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


#ifndef anubis_defaults_h
#define anubis_defaults_h

struct libnet_ethernet_hdr anubis_default_ethernet_header(const char *device);
anubis_ether_arp_t anubis_default_arp_header(void);
anubis_wol_hdr anubis_default_wol_header(void);
struct libnet_ipv4_hdr anubis_default_ip_header(const char *device);
anubis_options_t anubis_default_ip_options(void);
struct libnet_udp_hdr anubis_default_udp_header(void);
struct libnet_tcp_hdr anubis_default_tcp_header(void);
anubis_options_t anubis_default_tcp_options(void);
anubis_icmp_t anubis_default_icmp_header(void);
anubis_packet_raw_data_t anubis_default_rip_header(void);
anubis_message_hdr anubis_default_ssdp_header(void);
anubis_message_hdr anubis_default_http_header(void);
struct libnet_dhcpv4_hdr anubis_default_dhcp_header(const char *device);
char *anubis_default_device(void);
u_int8_t *anubis_default_mac_address(const char *device);
anubis_options_t anubis_default_dhcp_options(void);

#endif /* anubis_defaults_h */

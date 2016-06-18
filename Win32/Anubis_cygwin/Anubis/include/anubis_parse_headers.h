//
//  anubis_parse_headers.h
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


#ifndef anubis_parse_headers_h
#define anubis_parse_headers_h

#define ETHERTYPE_WOL 0x0842

#define CHECK_HEADER_TYPE(value, prefix) \
    if(value->type != json_object) { \
        anubis_err("%s: \"%s\" should be an object\n", prefix, prefix); \
        return; \
    }

#define CHECK_OPTION_TYPE(value, prefix) \
    if(value->type != json_array) { \
        anubis_err("%s: \"%s\" should be an array\n", prefix, prefix); \
        return; \
    }

#define COMPARE_FLAGS(ptr, x, s) \
    if(!strcasecmp(ptr, #x)) \
        s |= x;

#define COMPARE_DEFINE(ptr, x, set, required) \
    if(!strcasecmp(ptr, #x)) {\
        set = x; \
        required = 1; \
    }

#define CHECK_INTEGER_OR_STRING_TYPE(value, prefix) \
    if(value->type != json_integer && value->type != json_string) { \
        anubis_err("%s: \"%s\" should be an integer or a string\n", prefix, name); \
        continue; \
    }

#define CHECK_REQUIREMENT(x, prefix, field) \
    if(!x) \
        anubis_err("%s: \"%s\" is required\n", prefix, field);

#define CHECK_OPTION_REQUIREMENT(x, prefix, type, field) \
    if(!x) \
        anubis_err("%s: Type(%d): \"%s\" is required\n", prefix, type, field);

void anubis_parse_ethernet_hdr(json_value *json, struct libnet_ethernet_hdr *ethernet_hdr, const char *device);
void anubis_parse_arp_hdr(json_value *json, anubis_ether_arp_t *arp_hdr, const char *device);
void anubis_parse_wol_hdr(json_value *json, anubis_wol_hdr *wol_hdr, const char *device);
void anubis_parse_ip_hdr(json_value *json, struct libnet_ipv4_hdr *ip_hdr, const char *device);
void anubis_parse_ip_options(json_value *json, anubis_options_t *options, const char *device);
void anubis_parse_udp_hdr(json_value *json, struct libnet_udp_hdr *udp_hdr);
void anubis_parse_tcp_hdr(json_value *json, struct libnet_tcp_hdr *tcp_hdr);
void anubis_parse_tcp_options(json_value *json, anubis_options_t *options, const char *device);
void anubis_parse_icmp_hdr(json_value *json, anubis_icmp_t *icmp_hdr, const char *device);
void anubis_parse_rip_hdr(json_value *json, anubis_packet_raw_data_t *rip_hdr, const char *device);
void anubis_parse_ssdp_hdr(json_value *json, anubis_message_hdr *ssdp_hdr);
void anubis_parse_http_hdr(json_value *json, anubis_message_hdr *http_hdr);
void anubis_parse_dhcp_hdr(json_value *json, struct libnet_dhcpv4_hdr *dhcp_hdr, const char *device);
void anubis_parse_dhcp_options(json_value *json, anubis_options_t *options, const char *device);

void anubis_parse_raw_data(json_value *json, anubis_packet_raw_data_t *raw_data);
void anubis_parse_payload(json_value *json, anubis_packet_raw_data_t *payload);

#endif /* anubis_parse_headers_h */

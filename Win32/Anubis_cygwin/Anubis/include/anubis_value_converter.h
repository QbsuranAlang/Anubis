//
//  anubis_value_converter.h
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


#ifndef anubis_value_converter_h
#define anubis_value_converter_h

u_int8_t *anubis_mac_aton(const char *mac_address);
const char *anubis_mac_ntoa(u_int8_t *d);
char *anubis_ip_ttoa(u_int8_t flag);
char *anubis_ip_ftoa(u_int16_t flag);
char *anubis_tcp_ftoa(u_int8_t flag);
unsigned long long anubis_string_to_int(const char *s);
unsigned long long anubis_binary_to_int(const char *s, int length);
in_addr_t anubis_ip_aton(const char *ip_address);
const char *anubis_ip_ntoa(in_addr_t i);
in_addr_t anubis_hostname_to_ip_address(const char *hostname);
const char *anubis_message_status_code_to_phrase(u_int32_t code);
u_int32_t anubis_message_phrase_to_status_code(const char *phrase);
const SSL_METHOD *anubis_string_to_SSL_METOHD(const char *method, int role);

#define F(x, y) \
(!strncasecmp((x), (y), strlen(y)) && *((x) + strlen(y)) == '(' && *((x) + strlen(x) - 1) == ')')

#define IS_RANDOM(x) \
    F(x, "random")
u_int32_t anubis_random(char *expression);

#define IS_RANDOM_IP_ADDRESS(x) \
    F(x, "random_ip_address")
in_addr_t anubis_random_ip_address(char *expression);

#define IS_RANDOM_MAC_ADDRESS(x) \
    F(x, "random_mac_address")
u_int8_t *anubis_random_mac_address(char *expression);

#define IS_LOOKUP_MAC_ADDRESS(x) \
    F(x, "lookup_mac_address")
u_int8_t *anubis_lookup_mac_address(char *expression, const char *device);

#define IS_LOOKUP_IP_ADDRESS(x) \
    F(x, "lookup_ip_address")
in_addr_t anubis_lookup_ip_address(char *expression);

#define IS_MULTICAST_ADDRESS(x) \
    F(x, "multicast_address")
in_addr_t anubis_multicast_address(char *expression);

#define IS_PORT(x) \
    F(x, "port")
u_int16_t anubis_port(char *expression);

#endif /* anubis_value_converter_h */

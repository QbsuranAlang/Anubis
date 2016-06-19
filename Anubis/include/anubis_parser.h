//
//  anubis_parser.h
//  Anubis
//
//  Created by 聲華 陳 on 2016/3/30.
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


#ifndef anubis_parser_h
#define anubis_parser_h

void anubis_parse_mac_address(char *prefix, json_char *name, json_value *value,
                              u_int8_t *set_value, int length, const char *device,
                              int *required);
void anubis_parse_ip_address(char *prefix, json_char *name, json_value *value,
                             in_addr_t *set_value, int length, const char *device,
                             int *required);

void anubis_parse_4bytes_integer(char *prefix, json_char *name, json_value *value,
                                 u_int32_t *set_value, int *required);
void anubis_parse_2bytes_integer(char *prefix, json_char *name, json_value *value,
                                 u_int16_t *set_value, int *required);
void anubis_parse_byte_integer(char *prefix, json_char *name, json_value *value,
                               u_int8_t *set_value, int *required);
void anubis_parse_bit_binary(char *prefix, json_char *name, json_value *value,
                             u_int8_t *set_value, int length, int *required);

void anubis_parse_boolean(char *prefix, json_char *name, json_value *value,
                          int *set_value, int *required);
void anubis_parse_string(char *prefix, json_char *name, json_value *value,
                         char **set_value, int *required);

void anubis_parser(const char *filename);
void anubis_free_config(anubis_t *config);

#endif /* anubis_parser_h */

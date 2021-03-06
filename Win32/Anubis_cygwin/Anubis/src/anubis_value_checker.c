//
//  anubis_value_checker.c
//  Anubis
//
//  Created by 聲華 陳 on 2016/4/10.
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

int anubis_is_ip_address(char *ip_address) {
    in_addr_t ip_integer;
    int ret = inet_pton(AF_INET, ip_address, &ip_integer);
    if(ret == 0 || ret == -1)
        return 0;
    return 1;
}//end anubis_is_ip_address

int anubis_is_mac_address(char *mac_address) {
    u_int8_t *temp = NULL;
    int len;
    
    temp = libnet_hex_aton(mac_address, &len);
    if(!temp) {
        return 0;
    }//end if
    
    //length is not 6
    if(len != ETHER_ADDR_LEN) {
        free(temp);
        return 0;
    }//end if
    
    free(temp);
    return 1;
}//end anubis_is_mac_address
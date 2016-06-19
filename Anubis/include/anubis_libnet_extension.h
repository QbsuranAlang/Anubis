//
//  anubis_libnet_extension.h
//  Anubis
//
//  Created by 聲華 陳 on 2016/4/6.
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


#ifndef anubis_libnet_extension_h
#define anubis_libnet_extension_h

libnet_ptag_t
anubis_build_icmpv4_unreach(uint8_t type, uint8_t code, uint16_t sum, uint16_t mtu,
                            const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

libnet_t *
anubis_libnet_init(int injection_type, const char *device, char *err_buf);

libnet_ptag_t
anubis_build_rip(const uint8_t *data, uint32_t data_length,
                 const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

libnet_ptag_t
anubis_build_ssdp(const uint8_t *data, uint32_t data_length,
                  const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

libnet_ptag_t
anubis_build_http(const uint8_t *data, uint32_t data_length,
                  const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

libnet_ptag_t
anubis_build_dhcp_options(const uint8_t *data, uint32_t data_length,
                          const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

libnet_ptag_t
anubis_build_raw_data(const uint8_t *data, uint32_t data_length,
                      const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

#endif /* anubis_libnet_extension_h */

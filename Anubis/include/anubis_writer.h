//
//  anubis_writer.h
//  Anubis
//
//  Created by TUTU on 2016/4/1.
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


#ifndef anubis_writer_h
#define anubis_writer_h

#ifdef WIN32
bool anubis_init_winsock(void);
#endif

int anubis_build_fake_header(anubis_t *config, libnet_t *libnet_handle, int proto, int build_transport, int build_network);
int anubis_set_socket_option(anubis_t *config, int sd);
int anubis_bind_to_device(int sock, int family, const char *devicename, u_int16_t port);
void anubis_build_headers(libnet_t *handle, anubis_packet_t *packet);
u_int16_t anubis_checksum(u_int16_t *data, int len);

void anubis_write_data_link_or_network(anubis_t *config);
void anubis_write_transport(anubis_t *config);
void anubis_write_application(anubis_t *config);


#endif /* anubis_writer_h */

//
//  anubis_writer.h
//  Anubis
//
//  Created by 聲華 陳 on 2016/4/1.
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

void anubis_write_data_link_or_network(anubis_t *config);
void anubis_write_transport(anubis_t *config);
void anubis_write_application(anubis_t *config);

#endif /* anubis_writer_h */

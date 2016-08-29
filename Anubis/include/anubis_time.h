//
//  anubis_time.h
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


#ifndef anubis_time_h
#define anubis_time_h

void anubis_srand(void);
char *anubis_current_time_format(void);
long anubis_subtract_time(struct timeval from, struct timeval to);

#endif /* anubis_time_h */

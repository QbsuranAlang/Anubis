//
//  anubis_time.c
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


#include "anubis.h"

void anubis_srand(void) {
    /*from libnet/src/libnet_prand.c*/
    
    struct timeval seed;
    if (gettimeofday(&seed, NULL) == -1)
        srand((unsigned)time(NULL));
    
    /*
     *  More entropy then just seeding with time(2).
     */
    srandom((unsigned)(seed.tv_sec ^ seed.tv_usec));
}//end anubis_srand

char *anubis_current_time_format(void) {
    //2016-04-01 19:34:18.455 log[4016:246355] Hello, World!
    static char time_buffer[ANUBIS_BUFFER_SIZE][ANUBIS_BUFFER_SIZE];
    static int which = -1;
    char temp[ANUBIS_BUFFER_SIZE] = {0};
    long millisec = 0;
    struct tm *tm_info = NULL;
    struct timeval tv = {0};
    
    gettimeofday(&tv, NULL);
    
    millisec = lrint(tv.tv_usec/1000.0); // Round to nearest millisec
    if (millisec >= 1000) { // Allow for rounding up to nearest second
        millisec -= 1000;
        tv.tv_sec++;
    }//end if
    
    which = (which + 1 == ANUBIS_BUFFER_SIZE ? 0 : which + 1);
    memset(time_buffer[which], 0, sizeof(time_buffer[which]));
    /*
#ifndef __CYGWIN__
    tm_info = localtime(&tv.tv_sec);
    strftime(time_buffer[which], sizeof(time_buffer[which]), "%Y-%m-%d %H:%M:%S", tm_info);
#else
    time_t local_tv_sec = tv.tv_sec;
    tm_info = localtime(&local_tv_sec);
    strftime(time_buffer[which], sizeof(time_buffer[which]), "%H:%M:%S", tm_info);
#endif
    */
    time_t local_tv_sec = tv.tv_sec;
    tm_info = localtime(&local_tv_sec);
    strftime(time_buffer[which], sizeof(time_buffer[which]), "%H:%M:%S:", tm_info);
    
    memset(temp, 0, sizeof(temp));
    strlcpy(temp, time_buffer[which], sizeof(temp));
    memset(time_buffer[which], 0, sizeof(time_buffer[which]));
    
    snprintf(time_buffer[which], sizeof(time_buffer[which]), "%s%03d", temp, (int)(tv.tv_usec/1000) );
    return time_buffer[which];
}//end anubis_current_time_format

long anubis_subtract_time(struct timeval from, struct timeval to) {
    long microseconds = labs((to.tv_sec - from.tv_sec) * 1000000 + ((long)to.tv_usec - (long)from.tv_usec));

    return microseconds;
}//end anubis_subtract_time
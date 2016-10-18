//
//  anubis_stream.c
//  Anubis
//
//  Created by TUTU on 2016/3/30.
//
//
//        _____   _   _   _____   _   _
//       |_   _| | | | | |_   _| | | | |
//         | |   | | | |   | |   | | | |
//         | |   | |_| |   | |   | |_| |
//         |_|    \___/    |_|    \___/
//
//
//                               _       _
//       /\                     | |     (_)
//      /  \     _ __    _   _  | |__    _   ___
//     / /\ \   | '_ \  | | | | | '_ \  | | / __|
//    / ____ \  | | | | | |_| | | |_) | | | \__ \
//   /_/    \_\ |_| |_|  \__,_| |_.__/  |_| |___/


#include "anubis.h"

void anubis_perror(char *s) {
    anubis_err("%s: %s\n", s, strerror(errno));
}//end anubis_perror

void anubis_ssl_perror(char *s) {
    BIO *bio = BIO_new(BIO_s_mem());
    if(!bio)
        return;
    ERR_print_errors(bio);
    char *buf = NULL;
    BIO_get_mem_data(bio, &buf);
    anubis_err("%s: %s\n", s, buf);
    BIO_free(bio);
}

void anubis_in_stream(FILE *in_fp, char *out_buffer, int out_length) {
    int offset = 0;
    //char *tmp;
    char ch;
    int meet_slash = 0;
    
    if(in_fp == in_stream)
        anubis_out("> ");
    memset(out_buffer, 0, out_length);
    while((ch = fgetc(in_fp)) != EOF) {
        if(ch != '\n' && ch != '\r')
            out_buffer[offset++] = ch;
        if(offset + 1 > out_length) //out of range
            break;
        if(ch == '\r' || ch == '\n') {
            if(in_fp == in_stream)
                anubis_out("> ");
        }
        
        if(meet_slash) {
            meet_slash = 0;
            
            //escape sequences
            signed char c = 0;
            switch (ch) {
                case 'a': c = '\a'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'v': c = '\v'; break;
                default: break;
            }//end switch
            
            if(c == 0)
                continue;
            
            out_buffer[offset - 1] = 0;
            out_buffer[offset - 2] = c;
            offset--;
            
        }
        
        if(ch == '\\') {
            meet_slash = 1;
        }
    }//end while
    
    rewind(in_fp);
}//end anubis_in_stream

void anubis_in(char *out_buffer, int out_length) {
    
    anubis_in_stream(in_stream, out_buffer, out_length);
    fprintf(out_stream, "\n");
}//end anubis_in

FILE *anubis_null_stream(void) {
    FILE *null_stream;
    
    null_stream = fopen("/dev/null", "w");
    /*
#ifndef __CYGWIN__
    null_stream = fopen("/dev/null", "w");
#else
    null_stream = fopen("nul", "w");
#endif
    */
    if(!null_stream)
        anubis_perror("fopen()");
    
    return null_stream;
}//end anubis_anubis_null_stream

void anubis_err(const char *fmt, ...) {
    va_list ap;
    
    if(timestamp)
        fprintf(err_stream, "[%s] ", anubis_current_time_format());
    if(verbose)
        fprintf(err_stream, "[Error] ");
    
    va_start(ap, fmt);
    if (fmt != NULL)
        vfprintf(err_stream, fmt, ap);
    va_end(ap);
    
    fflush(err_stream);
}//end anubis_err

void anubis_out(const char *fmt, ...) {
    va_list ap;
    
    if(timestamp)
        fprintf(out_stream, "[%s] ", anubis_current_time_format());
    if(verbose)
        fprintf(out_stream, "[Output] ");
    
    va_start(ap, fmt);
    if (fmt != NULL)
        vfprintf(out_stream, fmt, ap);
    va_end(ap);
    
    fflush(out_stream);
}//end anubis_out

void anubis_verbose(const char *fmt, ...) {
    if(!verbose)
        return;
    
    if(timestamp)
        fprintf(out_stream, "[%s] ", anubis_current_time_format());
    if(verbose)
        fprintf(out_stream, "[Verbose] ");
    
    va_list ap;
    
    va_start(ap, fmt);
    if (fmt != NULL)
        vfprintf(out_stream, fmt, ap);
    va_end(ap);
    
    fflush(out_stream);
}//end anubis_verbose

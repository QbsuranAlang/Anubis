//
//  anubis_stream.c
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
    /*
    tmp = out_buffer;
    while((tmp = strchr(out_buffer, '\\'))) {
        signed char c = 0;
        switch (*(tmp + 1)) {
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
        
        printf("%s\n", out_buffer);
        *tmp = c;
        long move_length = out_buffer + strlen(out_buffer) - tmp - 2;
        if(move_length > 0) {
            memmove(tmp + 1, tmp + 2, move_length);
        }//end if
        out_buffer[strlen(out_buffer) - 1] = 0; //last character
        tmp += strlen(out_buffer) - move_length;
    }//end while
    rewind(in_fp);
     */
}//end anubis_in_stream

void anubis_in(char *out_buffer, int out_length) {
    
    anubis_in_stream(in_stream, out_buffer, out_length);
    /*
    char buffer[1024] = {};
    while(!feof(in_stream)) {
     
        anubis_out("> ");
        if(!fgets(buffer, sizeof(buffer), in_stream)) {
            if(errno)
                anubis_perror("fgets()");
            continue;
        }//end if
        
        //truncate newline
        if((tmp = strchr(buffer, '\n'))) {
            *tmp = 0;
        }//end if
        if((tmp = strchr(buffer, '\r'))) {
            *tmp = 0;
        }//end if
        
        //escape sequences
        while((tmp = strchr(buffer, '\\'))) {
            signed char c = 0;
            do {
                switch (*(tmp + 1)) {
                    case 'a': c = '\a'; break;
                    case 'b': c = '\b'; break;
                    case 'f': c = '\f'; break;
                    case 'n': c = '\n'; break;
                    case 'r': c = '\r'; break;
                    case 't': c = '\t'; break;
                    case 'v': c = '\v'; break;
                    default:
                        break;
                }//end switch
                if(c == 0)
                    break; //like goto
                
                *tmp = c;
                long move_length = buffer + strlen(buffer) - tmp - 2;
                if(move_length > 0) {
                    memmove(tmp + 1, tmp + 2, move_length);
                }//end if
                buffer[strlen(buffer) - 1] = 0;
            }//end do
            while(0);
        }//end if
        
        //read as much as can read
        snprintf(out_buffer, out_length, "%s%s", out_buffer, buffer);
        offset += strlen(buffer);
        if(offset + 1 >= out_length)
            break; //out of bound
        
        memset(buffer, 0, sizeof(buffer));
    }//end while
    rewind(in_stream); //flush in stream
    */
    
    fprintf(out_stream, "\n");
}//end anubis_in

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

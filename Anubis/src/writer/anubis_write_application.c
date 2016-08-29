//
//  anubis_write_application.c
//  Anubis
//
//  Created by TUTU on 2016/6/25.
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

static void anubis_write_datagram(anubis_t *config) {
    
    if(config->security_socket) {
        anubis_err("TUTU: Someday I will finish it, disabled \"Security\"\n");
        config->security_socket = 0;
    }
    
    if(config->security_socket) {
        /*
         u_int64_t outter_amount = 0;
         struct timeval timeout;
         struct sockaddr_in server_sin = {0};
         struct sockaddr_in client_sin = {0};
         
         int sd;
         
         SSL_CTX *ctx = NULL;
         
         if(config->comment)
         anubis_verbose("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
         
         if(config->security_socket) {
         SSL_load_error_strings();
         SSLeay_add_ssl_algorithms();
         const SSL_METHOD *meth = anubis_string_to_SSL_METOHD(config->sslMethod, config->role);
         if(!meth)
         return;
         ctx = SSL_CTX_new(meth);
         if (!ctx) {
         anubis_ssl_perror("SSL_CTX_new()");
         return;
         }//end if
         
         //load ceritificate
         if (SSL_CTX_use_certificate_file(ctx, config->certificate_file, SSL_FILETYPE_PEM) <= 0) {
         anubis_ssl_perror("SSL_CTX_use_certificate_file()");
         if(config->role == ANUBIS_ROLE_SERVER)
         return;
         }//end if
         
         //load private key
         if (SSL_CTX_use_PrivateKey_file(ctx, config->private_key_file, SSL_FILETYPE_PEM) <= 0) {
         anubis_ssl_perror("SSL_CTX_use_PrivateKey_file()");
         if(config->role == ANUBIS_ROLE_SERVER)
         return;
         }//end if
         
         if (!SSL_CTX_check_private_key(ctx)) {
         anubis_err("Socket[%d] Private key does not match the certificate public key\n", config->index);
         if(config->role == ANUBIS_ROLE_SERVER)
         return;
         }//end if
         }
         
         
         //open socket
         sd = socket(AF_INET, config->type, 0);
         //set socket option
         sd = anubis_set_socket_option(config, sd, 1);
         if(sd == -1)
         return;
         
         
         //whole config file injection
         if(config->infinite_loop)
         outter_amount = -1;
         else if(config->amount)
         outter_amount = config->amount;
         else
         outter_amount = 1;
         
         while(outter_amount--) {
         if(config->infinite_loop)
         outter_amount = -1;
         
         //set outter timeout
         #ifdef SO_SNDTIMEO
         memset(&timeout, 0, sizeof(timeout));
         timeout.tv_sec = config->send_timeout / 1000;
         timeout.tv_usec = config->send_timeout % 1000;
         if(config->send_timeout) {
         anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
         if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
         anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
         close(sd);
         return;
         }
         }//end if
         #endif
         
         #ifdef SO_RCVTIMEO
         memset(&timeout, 0, sizeof(timeout));
         timeout.tv_sec = config->recv_timeout / 1000;
         timeout.tv_usec = config->recv_timeout % 1000;
         if(config->recv_timeout) {
         anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
         if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
         anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
         close(sd);
         return;
         }
         }//end if
         #endif
         
         if(config->role == ANUBIS_ROLE_SERVER) {
         memset(&client_sin, 0, sizeof(client_sin));
         SSL *ssl = SSL_new(ctx);
         
         anubis_verbose("Waiting client...\n");
         while (DTLSv1_listen(ssl, &client_sin) <= 0);
         
         if(config->asynchronous) {
         pid_t pid = fork();
         if(pid == 0) {
         //here
         printf("here\n");
         exit(0);
         }//end if
         else if(pid == -1) {
         anubis_perror("fork()");
         continue;
         }//end else
         }//end if
         else {
         //here
         printf("here\n");
         }//end else
         
         }//end if server
         }//end while outter
         
         close(sd);
         if(ctx)
         SSL_CTX_free(ctx);
         */
    }
    else {
        char errbuf[LIBNET_ERRBUF_SIZE] = {0};
        u_int64_t inner_amount = 0;
        u_int64_t outter_amount = 0;
        libnet_t *libnet_handle = NULL;
        
        struct timeval timeout;
        int sd;
        int len;
        
#ifdef __CYGWIN__
        char device[ANUBIS_BUFFER_SIZE] = {0};
        snprintf(device, sizeof(device), "\\Device\\NPF_%s", config->device);
        libnet_handle = anubis_libnet_init(LIBNET_RAW4, device, errbuf);
#else
        libnet_handle = anubis_libnet_init(LIBNET_RAW4, config->device, errbuf);
#endif
        
        if(!libnet_handle) {
            anubis_err("%s\n", errbuf);
            return;
        }//end if
        
        if(config->comment)
            anubis_verbose("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
        
        //open socket
        sd = socket(AF_INET, config->type, 0);
        
        //set socket option
        sd = anubis_set_socket_option(config, sd);
        if(sd == -1)
            return;
        
        //whole config file injection
        if(config->infinite_loop)
            outter_amount = -1;
        else if(config->amount)
            outter_amount = config->amount;
        else
            outter_amount = 1;
        
        while(outter_amount--) {
            if(config->infinite_loop)
                outter_amount = -1;
            
            //set outter timeout
#ifdef SO_SNDTIMEO
            memset(&timeout, 0, sizeof(timeout));
            timeout.tv_sec = config->send_timeout / 1000;
            timeout.tv_usec = config->send_timeout % 1000;
            if(config->send_timeout) {
                anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
                if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
                    anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
                    close(sd);
                    return;
                }
            }//end if
#endif
            
#ifdef SO_RCVTIMEO
            memset(&timeout, 0, sizeof(timeout));
            timeout.tv_sec = config->recv_timeout / 1000;
            timeout.tv_usec = config->recv_timeout % 1000;
            if(config->recv_timeout) {
                anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
                if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                    anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
                    close(sd);
                    return;
                }
            }//end if
#endif
            
            //peer packet injection
            for(int i = 0 ; i < config->packets_count ; i++) {
                
                anubis_packet_t *packet = &config->packets[i];
                
                uint32_t content_length = 0;
                uint8_t *content = NULL;
                
                //set intter timeout
#ifdef SO_SNDTIMEO
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = packet->send_timeout / 1000;
                timeout.tv_usec = packet->send_timeout % 1000;
                if(packet->send_timeout) {
                    anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
                    if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
                        anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
                        close(sd);
                        return;
                    }
                }//end if
#endif
                
#ifdef SO_RCVTIMEO
                memset(&timeout, 0, sizeof(timeout));
                timeout.tv_sec = packet->recv_timeout / 1000;
                timeout.tv_usec = packet->recv_timeout % 1000;
                if(packet->recv_timeout) {
                    anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
                    if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                        anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
                        close(sd);
                        return;
                    }
                }//end if
#endif
                
                //inject amount
                if(packet->infinite_loop)
                    inner_amount = -1;
                else if(packet->amount)
                    inner_amount = packet->amount;
                else
                    inner_amount = 1;
                
                while(inner_amount--) {
                    if(packet->infinite_loop)
                        inner_amount = -1;
                    
                    if(packet->out_going) {
                        
                        if(!config->dst_ip && config->role == ANUBIS_ROLE_SERVER) {
                            anubis_err("Socket[%d] \"Receive Packet\" should be call before \"Send Packet\", skip the \"Send Packet\"\n", config->index);
                            continue;
                        }//end if
                        
                        if(packet->interactive) {
                            
                            struct sockaddr_in dst_sin = {0};
                            dst_sin.sin_family = AF_INET;
                            dst_sin.sin_addr.s_addr = config->dst_ip;
                            dst_sin.sin_port = htons(config->dst_port);
#if !(__linux) && !(__CYGWIN__)
                            dst_sin.sin_len = sizeof(dst_sin);
#endif
                            anubis_out("Send message to %s:%d\n", anubis_ip_ntoa(dst_sin.sin_addr.s_addr), ntohs(dst_sin.sin_port));
                            anubis_out("Interactive on(EOF to finish):\n");
                            char buffer[65535] = {0};
                            anubis_in(buffer, sizeof(buffer));
                            anubis_out("Read: %*s[EOF]\n", (int)strlen(buffer), buffer);
                            anubis_out("Length: %d\n", (int)strlen(buffer));
                            if(strlen(buffer) == 0) {
                                anubis_out("Not read anything\n");
                                continue;
                            }//end if
                            
                            int ret = (int)sendto(sd, buffer,
                                                  packet->send_length ? packet->send_length :
                                                  strlen(buffer),
                                                  0, (struct sockaddr *)&dst_sin, sizeof(dst_sin));
                            
                            if(ret < 0) {
                                anubis_perror("sendto()");
                            }//end if
                            else {
                                anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                                if(packet->dump_send)
                                    anubis_dump_application(buffer, (u_int32_t)strlen(buffer));
                            }//end else
                            
                        }//end if interactive
                        else if(packet->input_filename) {
                            struct sockaddr_in dst_sin = {0};
                            dst_sin.sin_family = AF_INET;
                            dst_sin.sin_addr.s_addr = config->dst_ip;
                            dst_sin.sin_port = htons(config->dst_port);
#if !(__linux) && !(__CYGWIN__)
                            dst_sin.sin_len = sizeof(dst_sin);
#endif
                            anubis_out("Send message to %s:%d\n", anubis_ip_ntoa(dst_sin.sin_addr.s_addr), ntohs(dst_sin.sin_port));
                            anubis_out("Read from file: %s\n", packet->input_filename);
                            char buffer[65535] = {0};
                            
                            //read from file
                            FILE *fp = fopen(packet->input_filename, "r+");
                            if(!fp) {
                                anubis_perror("fopen()");
                                continue;
                            }
                            anubis_in_stream(fp, buffer, sizeof(buffer));
                            fclose(fp);
                            
                            anubis_out("Read: %*s[EOF]\n", (int)strlen(buffer), buffer);
                            anubis_out("Length: %d\n", (int)strlen(buffer));
                            if(strlen(buffer) == 0) {
                                anubis_out("Not read anything\n");
                                continue;
                            }//end if
                            
                            int ret = (int)sendto(sd, buffer,
                                                  packet->send_length ? packet->send_length :
                                                  strlen(buffer),
                                                  0, (struct sockaddr *)&dst_sin, sizeof(dst_sin));
                            
                            if(ret < 0) {
                                anubis_perror("sendto()");
                            }//end if
                            else {
                                anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                                if(packet->dump_send)
                                    anubis_dump_application(buffer, (u_int32_t)strlen(buffer));
                            }//end else
                            
                        }//end if
                        else {
                            
                            libnet_clear_packet(libnet_handle);
                            anubis_build_headers(libnet_handle, packet);
                            if(libnet_handle->total_size == 0 || packet->layers == 0) {
                                anubis_err("Socket[%d] Empty packet\n", config->index);
                                continue;
                            }//end if
                            
                            //build fake header
                            if(anubis_build_fake_header(config, libnet_handle, IPPROTO_UDP, 1, 1) == -1) {
                                continue;
                            }//end if
                            
                            int c;
                            c = libnet_pblock_coalesce(libnet_handle, &content, &content_length);
                            if (c == -1) {
                                anubis_err("libnet_pblock_coalesce(): %s\n", libnet_geterror(libnet_handle));
                                continue;
                            }//end if
                            
                            struct sockaddr_in dst_sin = {0};
                            dst_sin.sin_family = AF_INET;
                            dst_sin.sin_addr.s_addr = config->dst_ip;
                            dst_sin.sin_port = htons(config->dst_port);
#if !(__linux) && !(__CYGWIN__)
                            dst_sin.sin_len = sizeof(dst_sin);
#endif
                            
                            anubis_out("Send message to %s:%d\n", anubis_ip_ntoa(dst_sin.sin_addr.s_addr), ntohs(dst_sin.sin_port));
                            int ret = (int)sendto(sd, content + LIBNET_IPV4_H + LIBNET_UDP_H,
                                                  packet->send_length ? packet->send_length :
                                                  content_length - LIBNET_IPV4_H - LIBNET_UDP_H,
                                                  0, (struct sockaddr *)&dst_sin, sizeof(dst_sin));
                            if(ret < 0) {
                                anubis_perror("sendto()");
                            }//end if
                            else {
                                anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                                if(packet->dump_send)
                                    anubis_dump_libnet_content(libnet_handle, 1, 1);
                            }//end else
                            
#ifndef __CYGWIN__
                            //free
                            if (libnet_handle->aligner > 0) {
                                content = content - libnet_handle->aligner;
                            }//end if
                            free(content);
#endif
                            content = NULL;
                        }//end else
                        
                        if(config->role == ANUBIS_ROLE_CLIENT) {
                            //maybe next is "Receive packet", this is next source ip address
                            config->src_port = ntohs(config->dst_port);
                        }//end if
                    }//end if send
                    else {
                        
                        if(!config->src_port && config->role == ANUBIS_ROLE_CLIENT) {
                            anubis_err("Socket[%d] \"Send Packet\" should be call before \"Receive Packet\", skip the \"Receive Packet\"\n", config->index);
                            continue;
                        }//end if
                        
                        char buffer[65535] = {0};
                        
                        struct sockaddr_in src_sin = {0};
                        src_sin.sin_family = AF_INET;
                        src_sin.sin_addr.s_addr = INADDR_ANY;
                        src_sin.sin_port = htons(config->src_port);
#if !(__linux) && !(__CYGWIN__)
                        src_sin.sin_len = sizeof(src_sin);
#endif
                        anubis_out("Receiving from localhost:%d\n", config->src_port);
                        len = sizeof(src_sin);
                        
                        int ret = (int)recvfrom(sd, buffer, sizeof(buffer),
                                                0,
                                                (struct sockaddr *)&src_sin, (socklen_t *)&len);
                        if(ret < 0) {
                            if(errno == EAGAIN) {
                                anubis_verbose("Timeout\n");
                                break;
                            }//end if
                            if(errno == EAGAIN && packet->read_until_timeout) {
                                break;
                            }//end if
                            else {
                                anubis_perror("recvfrom()");
                            }//end if
                        }//end if
                        else {
                            anubis_out("Read %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                            if(packet->dump_recv)
                                anubis_dump_application(buffer, ret);
                            
                            if(config->role == ANUBIS_ROLE_SERVER) {
                                //maybe next is "Send packet", this is next destination ip address
                                config->dst_ip = src_sin.sin_addr.s_addr;
                                config->dst_port = ntohs(src_sin.sin_port);
                            }
                            anubis_out("Received from %s:%d\n", anubis_ip_ntoa(src_sin.sin_addr.s_addr), ntohs(src_sin.sin_port));
                            if(packet->output_filename) {
                                anubis_out("Write to %s\n", packet->output_filename);
                                do {
                                    FILE *fp = fopen(packet->output_filename, "a+");
                                    if(!fp) {
                                        anubis_err("fopen()");
                                        break;
                                    }//end if
                                    fprintf(fp, "%*s", ret, buffer);
                                    fflush(fp);
                                    fclose(fp);
                                }
                                while(0);
                            }
                        }//end else
                    }//end if receive
                    
                    if(packet->interval) {
                        anubis_wait_microsecond(packet->interval);
                    }//end if
                }//end while
            }//end for
            
            if(config->interval) {
                anubis_wait_microsecond(config->interval);
            }//end if
        }//end while
        
        //free
        shutdown(sd, SHUT_RDWR);
        close(sd);
        if(libnet_handle)
            libnet_destroy(libnet_handle);
    }
    
}//end anubis_write_datagram

static void anubis_handle_tcp_socket(anubis_t *config, u_int64_t outter_amount, int sd, struct sockaddr_in *sin, SSL_CTX *ctx) {
    if(config->role == ANUBIS_ROLE_SERVER) {
        anubis_out("Client: %s:%d is connected\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
    }
    else if(config->role == ANUBIS_ROLE_CLIENT) {
        anubis_out("Server: %s:%d is connected\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
    }
    
    libnet_t *libnet_handle = NULL;
    u_int64_t inner_amount = 0;
    struct timeval timeout;
    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    SSL *ssl = NULL;
    
#ifdef __CYGWIN__
    char device[ANUBIS_BUFFER_SIZE] = {0};
    snprintf(device, sizeof(device), "\\Device\\NPF_%s", config->device);
    libnet_handle = anubis_libnet_init(LIBNET_RAW4, device, errbuf);
#else
    libnet_handle = anubis_libnet_init(LIBNET_RAW4, config->device, errbuf);
#endif
    
    if(!libnet_handle) {
        anubis_err("%s\n", errbuf);
        return;
    }//end if
    
    if(config->security_socket) {
        /* ----------------------------------------------- */
        /* TCP connection is ready. Do server side SSL. */
        
        ssl = SSL_new(ctx);
        if(!ssl) {
            anubis_ssl_perror("SSL_new()");
            goto BYE;
        }
        
        if(SSL_set_fd(ssl, sd) <= 0) {
            anubis_ssl_perror("SSL_set_fd()");
            goto BYE;
        }
        
        if(config->role == ANUBIS_ROLE_SERVER) {
            if(SSL_accept(ssl) <= 0) {
                anubis_ssl_perror("SSL_accept()");
                goto BYE;
            }
        }
        else if(config->role == ANUBIS_ROLE_CLIENT) {
            if(SSL_connect(ssl) <= 0) {
                anubis_ssl_perror("SSL_connect()");
                goto BYE;
            }
        }
        if(config->certificate_information && config->role == ANUBIS_ROLE_CLIENT) {
            anubis_dump_server_certificate(ssl);
        }//end if show certficate
    }
    
    //peer packet injection
    for(int i = 0 ; i < config->packets_count ; i++) {
        anubis_packet_t *packet = &config->packets[i];
        
        uint32_t content_length = 0;
        uint8_t *content = NULL;
        
        //set intter timeout
#ifdef SO_SNDTIMEO
        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = packet->send_timeout / 1000;
        timeout.tv_usec = packet->send_timeout % 1000;
        if(packet->send_timeout) {
            anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
            if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
                anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
                close(sd);
                return;
            }
        }//end if
#endif
        
#ifdef SO_RCVTIMEO
        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = packet->recv_timeout / 1000;
        timeout.tv_usec = packet->recv_timeout % 1000;
        if(packet->recv_timeout) {
            anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
            if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
                close(sd);
                return;
            }
        }//end if
#endif
        
        //inject amount
        if(packet->infinite_loop)
            inner_amount = -1;
        else if(packet->amount)
            inner_amount = packet->amount;
        else
            inner_amount = 1;
        
        while(inner_amount--) {
            if(packet->infinite_loop)
                inner_amount = -1;
            
            if(packet->out_going) {
                if(packet->interactive) {
                    anubis_out("Send message to %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                    anubis_out("Interactive on(EOF to finish):\n");
                    char buffer[65535] = {0};
                    anubis_in(buffer, sizeof(buffer));
                    anubis_out("Read: %*s[EOF]\n", (int)strlen(buffer), buffer);
                    anubis_out("Length: %d\n", (int)strlen(buffer));
                    if(strlen(buffer) == 0) {
                        anubis_out("Not read anything\n");
                        continue;
                    }//end if
                    
                    int ret = 0;
                    if(!config->security_socket) {
                        ret = (int)send(sd, buffer,
                                        packet->send_length ? packet->send_length :
                                        strlen(buffer),
                                        0);
                    }
                    else {
                        ret = SSL_write(ssl, buffer, packet->send_length ? packet->send_length : (int)strlen(buffer));
                    }
                    
                    if(ret < 0) {
                        if(!config->security_socket)
                            anubis_perror("send()");
                        else
                            anubis_ssl_perror("SSL_write()");
                    }//end if
                    else if(ret == 0) {
                        if(config->role == ANUBIS_ROLE_SERVER) {
                            anubis_out("Connection with client %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                        }
                        else if(config->role == ANUBIS_ROLE_CLIENT) {
                            anubis_out("Connection with server %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                        }
                        goto BYE;
                    }
                    else {
                        anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                        if(packet->dump_send)
                            anubis_dump_application(buffer, (u_int32_t)strlen(buffer));
                    }//end else
                }
                else if(packet->input_filename) {
                    anubis_out("Send message to %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                    anubis_out("Read from file: %s\n", packet->input_filename);
                    char buffer[65535] = {0};
                    //read from file
                    FILE *fp = fopen(packet->input_filename, "r+");
                    if(!fp) {
                        anubis_perror("fopen()");
                        continue;
                    }
                    anubis_in_stream(fp, buffer, sizeof(buffer));
                    fclose(fp);
                    anubis_out("Read: %*s[EOF]\n", (int)strlen(buffer), buffer);
                    anubis_out("Length: %d\n", (int)strlen(buffer));
                    if(strlen(buffer) == 0) {
                        anubis_out("Not read anything\n");
                        continue;
                    }//end if
                    
                    int ret = 0;
                    if(!config->security_socket) {
                        ret = (int)send(sd, buffer,
                                        packet->send_length ? packet->send_length :
                                        strlen(buffer),
                                        0);
                    }
                    else {
                        ret = SSL_write(ssl, buffer, packet->send_length ? packet->send_length : (int)strlen(buffer));
                    }
                    
                    if(ret < 0) {
                        if(!config->security_socket)
                            anubis_perror("send()");
                        else
                            anubis_ssl_perror("SSL_write()");
                    }//end if
                    else if(ret == 0) {
                        if(config->role == ANUBIS_ROLE_SERVER) {
                            anubis_out("Connection with client %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                        }
                        else if(config->role == ANUBIS_ROLE_CLIENT) {
                            anubis_out("Connection with server %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                        }
                        goto BYE;
                    }
                    else {
                        anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                        if(packet->dump_send)
                            anubis_dump_application(buffer, (u_int32_t)strlen(buffer));
                    }//end else
                }//end if input from file
                else {
                    libnet_clear_packet(libnet_handle);
                    anubis_build_headers(libnet_handle, packet);
                    if(libnet_handle->total_size == 0 || packet->layers == 0) {
                        anubis_err("Socket[%d] Empty packet\n", config->index);
                        continue;
                    }//end if
                    
                    //build fake header
                    if(anubis_build_fake_header(config, libnet_handle, IPPROTO_TCP, 1, 1) == -1) {
                        continue;
                    }//end if
                    
                    int c;
                    c = libnet_pblock_coalesce(libnet_handle, &content, &content_length);
                    if (c == -1) {
                        anubis_err("libnet_pblock_coalesce(): %s\n", libnet_geterror(libnet_handle));
                        continue;
                    }//end if
                    anubis_out("Send message to %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                    
                    int ret = 0;
                    if(!config->security_socket) {
                        ret = (int)send(sd,
                                        content + LIBNET_IPV4_H + LIBNET_TCP_H,
                                        packet->send_length ? packet->send_length :
                                        content_length - LIBNET_IPV4_H - LIBNET_TCP_H,
                                        0);
                    }
                    else {
                        ret = SSL_write(ssl, content + LIBNET_IPV4_H + LIBNET_TCP_H,
                                        packet->send_length ? packet->send_length :
                                        content_length - LIBNET_IPV4_H - LIBNET_TCP_H);
                    }
                    
                    if(ret < 0) {
                        if(!config->security_socket)
                            anubis_perror("send()");
                        else
                            anubis_ssl_perror("SSL_write()");
                    }//end if
                    else if(ret == 0) {
                        goto BYE;
                    }
                    else {
                        anubis_out("Write %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                        if(packet->dump_send)
                            anubis_dump_libnet_content(libnet_handle, 1, 1);
                    }//end else
                    
#ifndef __CYGWIN__
                    //free
                    if (libnet_handle->aligner > 0) {
                        content = content - libnet_handle->aligner;
                    }//end if
                    free(content);
#endif
                    content = NULL;
                }
            }//end if send
            else {
                
                anubis_out("Receiving from %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                
                char buffer[65535] = {0};
                int ret = 0;
                if(!config->security_socket) {
                    ret = (int)recv(sd, buffer, sizeof(buffer), 0);
                }
                else {
                    ret = SSL_read(ssl, buffer, sizeof(buffer));
                }//end
                
                if(ret < 0) {
                    if(errno == EAGAIN) {
                        anubis_verbose("Timeout\n");
                        break;
                    }//end if
                    if(errno == EAGAIN && packet->read_until_timeout) {
                        break;
                    }//end if
                    else {
                        if(!config->security_socket)
                            anubis_perror("recv()");
                        else
                            anubis_ssl_perror("SSL_read()");
                    }//end if
                }//end if
                else if(ret == 0) {
                    goto BYE;
                }
                else {
                    anubis_out("Read %d byte%s", ret, ret > 0 ? "s\n" : "\n");
                    if(packet->dump_recv)
                        anubis_dump_application(buffer, ret);
                    anubis_out("Received from %s:%d\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
                    if(packet->output_filename) {
                        anubis_out("Write to %s\n", packet->output_filename);
                        do {
                            FILE *fp = fopen(packet->output_filename, "a+");
                            if(!fp) {
                                anubis_err("fopen()");
                                break;
                            }//end if
                            fprintf(fp, "%*s", ret, buffer);
                            fflush(fp);
                            fclose(fp);
                        }
                        while(0);
                    }
                }//end else
                
            }//end receive
            if(packet->interval) {
                anubis_wait_microsecond(packet->interval);
            }//end if
        }//end while
    }//end for
    
BYE:
    if(config->role == ANUBIS_ROLE_SERVER) {
        anubis_out("Connection with client %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
        if(config->asynchronous)
            anubis_out("Waiting client...\n");
    }
    else if(config->role == ANUBIS_ROLE_CLIENT) {
        anubis_out("Connection with server %s:%d is closed\n", anubis_ip_ntoa(sin->sin_addr.s_addr), ntohs(sin->sin_port));
    }
    
    if(ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    shutdown(sd, SHUT_RDWR);
    close(sd);
    if(libnet_handle)
        libnet_destroy(libnet_handle);
}//end anubis_handle_tcp_socket

static void anubis_write_stream(anubis_t *config) {
    u_int64_t outter_amount = 0;
    struct timeval timeout;
    struct sockaddr_in server_sin = {0};
    
    int sd;
    
    SSL_CTX *ctx = NULL;
    
    if(config->comment)
        anubis_verbose("Socket[%d] Comment: \"%s\"\n", config->index, config->comment);
    
    if(config->security_socket) {
        SSL_load_error_strings();
        SSLeay_add_ssl_algorithms();
        const SSL_METHOD *meth = anubis_string_to_SSL_METOHD(config->sslMethod, config->role);
        if(!meth)
            return;
        ctx = SSL_CTX_new(meth);
        if (!ctx) {
            anubis_ssl_perror("SSL_CTX_new()");
            return;
        }//end if
        
        if(config->role == ANUBIS_ROLE_SERVER) {
            //must use
            if (SSL_CTX_use_certificate_file(ctx, config->certificate_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_certificate_file()");
                return;
            }//end if
            else {
                anubis_verbose("Using certificate: \"%s\"\n", config->certificate_file);
            }
            
            //load private key
            if (SSL_CTX_use_PrivateKey_file(ctx, config->private_key_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_PrivateKey_file()");
                return;
            }//end if
            else {
                anubis_verbose("Using private key: \"%s\"\n", config->private_key_file);
            }
            
            if(!SSL_CTX_check_private_key(ctx)) {
                anubis_err("Socket[%d] Private key does not match the certificate public key\n", config->index);
                return;
            }//end if
        }
        else if(config->role == ANUBIS_ROLE_CLIENT) {
            //must use
            if (config->certificate_file && config->private_key_file &&
                SSL_CTX_use_certificate_file(ctx, config->certificate_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_certificate_file()");
                return;
            }//end if
            else if(config->certificate_file && config->private_key_file) {
                anubis_verbose("Using certificate: \"%s\"\n", config->certificate_file);
            }
            
            //load private key
            if (config->certificate_file && config->private_key_file &&
                SSL_CTX_use_PrivateKey_file(ctx, config->private_key_file, SSL_FILETYPE_PEM) <= 0) {
                anubis_ssl_perror("SSL_CTX_use_PrivateKey_file()");
                return;
            }//end if
            else if(config->certificate_file && config->private_key_file) {
                anubis_verbose("Using private key: \"%s\"\n", config->private_key_file);
            }
            
            if(config->certificate_file && config->private_key_file &&
               !SSL_CTX_check_private_key(ctx)) {
                anubis_err("Socket[%d] Private key does not match the certificate public key\n", config->index);
                return;
            }//end if
        }
        
        //load ceritificate
        if (config->certificate_file &&
            SSL_CTX_use_certificate_file(ctx, config->certificate_file, SSL_FILETYPE_PEM) <= 0) {
            anubis_ssl_perror("SSL_CTX_use_certificate_file()");
            if(config->role == ANUBIS_ROLE_SERVER)
                return;
        }//end if
        else if(config->certificate_file) {
            anubis_verbose("Using certificate: \"%s\"\n", config->certificate_file);
        }
        
        //load private key
        if (config->private_key_file &&
            SSL_CTX_use_PrivateKey_file(ctx, config->private_key_file, SSL_FILETYPE_PEM) <= 0) {
            anubis_ssl_perror("SSL_CTX_use_PrivateKey_file()");
            if(config->role == ANUBIS_ROLE_SERVER)
                return;
        }//end if
        else if(config->private_key_file) {
            anubis_verbose("Using private key: \"%s\"\n", config->private_key_file);
        }
        
        if(config->certificate_file && config->private_key_file &&
           !SSL_CTX_check_private_key(ctx)) {
            anubis_err("Socket[%d] Private key does not match the certificate public key\n", config->index);
            if(config->role == ANUBIS_ROLE_SERVER)
                return;
        }//end if
    }
    
    
    //open socket
    sd = socket(AF_INET, config->type, 0);
    //set socket option
    sd = anubis_set_socket_option(config, sd);
    if(sd == -1)
        return;
    
    if(config->role == ANUBIS_ROLE_SERVER) {
        //listen
        if(listen(sd, config->max_connection) == -1) {
            anubis_perror("listen()");
            return;
        }//end if
    }
    else if(config->role == ANUBIS_ROLE_CLIENT) {
        //connect
        memset(&server_sin, 0, sizeof(server_sin));
        server_sin.sin_family = AF_INET;
        server_sin.sin_addr.s_addr = config->dst_ip;
        server_sin.sin_port = htons(config->dst_port);
#if !(__linux) && !(__CYGWIN__)
        server_sin.sin_len = sizeof(struct sockaddr_in);
#endif
        
        if(connect(sd, (struct sockaddr *)&server_sin, sizeof(server_sin)) == -1) {
            anubis_perror("connect()");
            return;
        }//end if
    }//end if
    
    //whole config file injection
    if(config->infinite_loop)
        outter_amount = -1;
    else if(config->amount)
        outter_amount = config->amount;
    else
        outter_amount = 1;
    
    while(outter_amount--) {
        if(config->infinite_loop)
            outter_amount = -1;
        
        //set outter timeout
#ifdef SO_SNDTIMEO
        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = config->send_timeout / 1000;
        timeout.tv_usec = config->send_timeout % 1000;
        if(config->send_timeout) {
            anubis_verbose("Setting socket option: \"SO_SNDTIMEO\"\n");
            if(setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == -1) {
                anubis_perror("setsockopt(): set SO_SNDTIMEO failed");
                close(sd);
                return;
            }
        }//end if
#endif
        
#ifdef SO_RCVTIMEO
        memset(&timeout, 0, sizeof(timeout));
        timeout.tv_sec = config->recv_timeout / 1000;
        timeout.tv_usec = config->recv_timeout % 1000;
        if(config->recv_timeout) {
            anubis_verbose("Setting socket option: \"SO_RCVTIMEO\"\n");
            if(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
                anubis_perror("setsockopt(): set SO_RCVTIMEO failed");
                close(sd);
                return;
            }
        }//end if
#endif
        
        if(config->role == ANUBIS_ROLE_SERVER) {
            
            int client_sd;
            struct sockaddr_in client_sin = {0};
            socklen_t len = sizeof(client_sin);
            anubis_out("Waiting client...\n");
            if((client_sd = accept(sd, (struct sockaddr *)&client_sin, &len)) == -1) {
                anubis_perror("accept()");
                continue;
            }//end if
            else {
                if(config->asynchronous) {
                    pid_t pid = fork();
                    if(pid == 0) {
                        anubis_handle_tcp_socket(config, outter_amount, client_sd, &client_sin, ctx);
                        exit(0);
                    }//end if
                    else if(pid == -1) {
                        anubis_perror("fork()");
                        continue;
                    }//end else
                }//end if
                else {
                    anubis_handle_tcp_socket(config, outter_amount, client_sd, &client_sin, ctx);
                }//end else
            }//end else
        }//end if server
        else if(config->role == ANUBIS_ROLE_CLIENT) {
            anubis_handle_tcp_socket(config, outter_amount, sd, &server_sin, ctx);
        }//end if client
        
        if(config->interval) {
            anubis_wait_microsecond(config->interval);
        }//end if
    }//end outter loop
    close(sd);
    if(ctx)
        SSL_CTX_free(ctx);
}//end anubis_write_stream

void anubis_write_application(anubis_t *config) {
    
    if(config->type == SOCK_DGRAM) {
        if(config->role == ANUBIS_ROLE_SERVER)
            anubis_verbose("Socket[%d] I am a datagram server\n", config->index);
        else if(config->role == ANUBIS_ROLE_CLIENT)
            anubis_verbose("Socket[%d] I am a datagram client\n", config->index);
        
        anubis_write_datagram(config);
    }//end if udp
    else if(config->type == SOCK_STREAM) {
        if(config->role == ANUBIS_ROLE_SERVER)
            anubis_verbose("Socket[%d] I am a stream server\n", config->index);
        else if(config->role == ANUBIS_ROLE_CLIENT)
            anubis_verbose("Socket[%d] I am a stream client\n", config->index);
        
        anubis_write_stream(config);
    }//end if tcp
    
}//end anubis_write_application
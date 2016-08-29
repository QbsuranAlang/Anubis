//
//  anubis_parser.c
//  Anubis
//
//  Created by TUTU on 2016/3/30.
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

#define SET_REQUIRED(x) do { \
    if(x) \
        *x = 1; \
    } \
    while(0)

#pragma mark parse fields
void anubis_parse_mac_address(const char *prefix, const json_char *name, const json_value *value,
                              u_int8_t *set_value, int length, const char *device,
                              int *required) {
    if(value->type != json_string) {
        anubis_err("%s: \"%s\" should be a string\n", prefix, name);
        return;
    }//end if
    
    u_int8_t *ptr = NULL;
    if(!strcasecmp(value->u.string.ptr, "Myself")) {
        libnet_t *handle = NULL;
	    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
#ifdef __CYGWIN__
	    char device2[ANUBIS_BUFFER_SIZE] = {0};
	    snprintf(device2, sizeof(device2), "\\Device\\NPF_%s", device);
	    handle = anubis_libnet_init(LIBNET_RAW4, device2, errbuf);
#else
	    handle = anubis_libnet_init(LIBNET_RAW4, device, errbuf);
#endif
        if(!handle) {
            anubis_err("%s\n", errbuf);
            return;
        }//end if
        
        ptr = (u_int8_t *)libnet_get_hwaddr(handle);
        if(!ptr) {
            anubis_err("%s\n", libnet_geterror(handle));
            libnet_destroy(handle);
            return;
        }//end if
        libnet_destroy(handle);
    }//end if myself
    else if(!strcasecmp(value->u.string.ptr, "Broadcast") || !strcasecmp(value->u.string.ptr, "ff:ff:ff:ff:ff:ff")) {
        ptr = (u_int8_t *)"\xff\xff\xff\xff\xff\xff";
    }//end if
    else if(IS_RANDOM_MAC_ADDRESS(value->u.string.ptr)) {
        ptr = anubis_random_mac_address(value->u.string.ptr);
    }//end if
    else if(IS_LOOKUP_MAC_ADDRESS(value->u.string.ptr)) {
        ptr = anubis_lookup_mac_address(value->u.string.ptr, device);
    }//end if
    else {
        ptr = anubis_mac_aton(value->u.string.ptr);
    }//end else
    
    if(!ptr)
        return;
    
    memmove(set_value, ptr, length);
    SET_REQUIRED(required);
}//end anubis_parse_mac_address

void anubis_parse_ip_address(const char *prefix, const json_char *name, const json_value *value,
                             in_addr_t *set_value, int length, const char *device,
                             int *required) {
    if(value->type != json_string) {
        anubis_err("%s: \"%s\" should be a string\n", prefix, name);
        return;
    }//end if
    
    in_addr_t addr = 0;
    if(!strcasecmp(value->u.string.ptr, "Myself")) {
        libnet_t *handle = NULL;
	    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
#ifdef __CYGWIN__
	    char device2[ANUBIS_BUFFER_SIZE] = {0};
	    snprintf(device2, sizeof(device2), "\\Device\\NPF_%s", device);
	    handle = anubis_libnet_init(LIBNET_RAW4, device2, errbuf);
#else
	    handle = anubis_libnet_init(LIBNET_RAW4, device, errbuf);
#endif
	    
        if(!handle) {
            anubis_err("%s\n", errbuf);
            return;
        }//end if
        
        addr = libnet_get_ipaddr4(handle);
        if(addr == -1) {
            anubis_err("%s\n", libnet_geterror(handle));
            libnet_destroy(handle);
            return;
        }//end if
        libnet_destroy(handle);
    }//end if myself
    else if(!strcasecmp(value->u.string.ptr, "Default-Route")) {
        anubis_verbose("Getting default route...\n");
        addr = anubis_default_route();
    }
    else if(!strcasecmp(value->u.string.ptr, "Broadcast") || !strcasecmp(value->u.string.ptr, "255.255.255.255")) {
        /*255.255.255.255 = 0xFFFFFFFF = -1, damn*/
        addr = INADDR_BROADCAST;
    }//end if
    else if(!strcasecmp(value->u.string.ptr, "0.0.0.0")) {
        addr = INADDR_ANY;
    }
    else if(IS_RANDOM_IP_ADDRESS(value->u.string.ptr)) {
        addr = anubis_random_ip_address(value->u.string.ptr);
    }//end if
    else if(IS_LOOKUP_IP_ADDRESS(value->u.string.ptr)) {
        addr = anubis_lookup_ip_address(value->u.string.ptr);
    }//end if
    else if(IS_MULTICAST_ADDRESS(value->u.string.ptr)) {
        addr = anubis_multicast_address(value->u.string.ptr);
    }//end if
    else if(anubis_is_ip_address(value->u.string.ptr)) {
        addr = anubis_ip_aton(value->u.string.ptr);
        if(addr == -1)
            return;
    }//end if is ip address
    else {
        addr = anubis_hostname_to_ip_address(value->u.string.ptr);
        if(addr == -1)
            return;
    }//end else
    
    memmove(set_value, &addr, length);
    SET_REQUIRED(required);
}//end anubis_parse_ip_address

void anubis_parse_4bytes_integer(const char *prefix, const json_char *name, const json_value *value,
                                 u_int32_t *set_value, int *required) {
    if(value->type == json_integer) {
        *set_value = (u_int32_t)value->u.integer;
        SET_REQUIRED(required);
    }//end if
    else if(value->type == json_string) {
        *set_value = (u_int32_t)anubis_string_to_int(value->u.string.ptr);
        SET_REQUIRED(required);
    }//end if
    else {
        anubis_err("%s: \"%s\" should be an integer or a string\n", prefix, name);
    }//end else
}//end anubis_parse_4bytes_integer

void anubis_parse_2bytes_integer(const char *prefix, const json_char *name, const json_value *value,
                                 u_int16_t *set_value, int *required) {
    if(value->type == json_integer) {
        *set_value = (u_int16_t)value->u.integer;
        SET_REQUIRED(required);
    }//end if
    else if(value->type == json_string) {
        *set_value = (u_int16_t)anubis_string_to_int(value->u.string.ptr);
        SET_REQUIRED(required);
    }//end if
    else {
        anubis_err("%s: \"%s\" should be an integer or a string\n", prefix, name);
    }//end else
}//end anubis_parse_2bytes_integer

void anubis_parse_byte_integer(const char *prefix, const json_char *name, const json_value *value,
                               u_int8_t *set_value, int *required) {
    if(value->type == json_integer) {
        *set_value = (u_int8_t)value->u.integer;
        SET_REQUIRED(required);
    }//end if
    else if(value->type == json_string) {
        *set_value = (u_int8_t)anubis_string_to_int(value->u.string.ptr);
        SET_REQUIRED(required);
    }//end if
    else {
        anubis_err("%s: \"%s\" should be an integer or a string\n", prefix, name);
    }//end else
}//end anubis_parse_byte_integer

void anubis_parse_boolean(const char *prefix, const json_char *name, const json_value *value,
                          int *set_value, int *required) {
    if(value->type == json_integer) {
        *set_value = (int)value->u.integer;
        SET_REQUIRED(required);
    }//end if
    else if(value->type == json_string) {
        if(!strcasecmp(value->u.string.ptr, "enable") || !strcasecmp(value->u.string.ptr, "1")) {
            *set_value = 1;
            SET_REQUIRED(required);
        }//end if
        else if(!strcasecmp(value->u.string.ptr, "disable") || !strcasecmp(value->u.string.ptr, "0")) {
            *set_value = 0;
            SET_REQUIRED(required);
        }//end if
        else {
            anubis_err("%s: \"%s\" should be \"enable\", \"disable\", 1 or 0\n", prefix, name);
        }//end else
    }//end if
    else {
        anubis_err("%s: \"%s\" should be a string or an integer\n", prefix, name);
    }//end else
}//end anubis_parse_boolean

void anubis_parse_string(const char *prefix, const json_char *name, const json_value *value,
                         char **set_value, int *required) {
    if(value->type != json_string) {
        anubis_err("%s: \"%s\" should be a string\n", prefix, name);
        return;
    }//end if
    if(value->u.string.length == 0) {
        anubis_err("%s: \"%s\" length is zero\n", prefix, name);
        return;
    }
    *set_value = value->u.string.ptr;
    SET_REQUIRED(required);
}//end anubis_parse_string

void anubis_parse_bit_binary(const char *prefix, const json_char *name, const json_value *value,
                              u_int8_t *set_value, int length, int *required) {
    if(value->type != json_string) {
        anubis_err("%s: \"%s\" should be a string\n", prefix, name);
        return;
    }//end if
    
    if(value->u.string.length != length) {
        anubis_err("%s: \"%s\" length should be %d\n", prefix, name, length);
        return;
    }//end if
    
    if(length > ANUBIS_BUFFER_SIZE) {
        anubis_err("%s: \"%s\" length should be less %d\n", prefix, name, ANUBIS_BUFFER_SIZE);
        return;
    }//end if
    
    //check charater set
    char buf1[ANUBIS_BUFFER_SIZE] = {0};
    char buf2[ANUBIS_BUFFER_SIZE] = {0};
    snprintf(buf1, sizeof(buf1), "%*s", length, value->u.string.ptr);
    sscanf(buf1, "%[01]", buf2);
    if(strlen(buf2) != length) {
        anubis_err("%s: \"%s\" should be 1 or 0\n", prefix, name);
        return;
    }//end if
    
    *set_value = (u_int8_t)anubis_binary_to_int(value->u.string.ptr, length);
    SET_REQUIRED(required);
}//end anubis_parse_bit_binary

void anubis_parse_host_list(const char *prefix, const json_char *name, const json_value *value,
                            in_addr_t **set_value, int *length, const char *device,
                            int *required) {
    
    CHECK_ARRAY_TYPE(value, prefix, name);
    
    for(int i = 0 ; i < value->u.array.length ; i++) {
        json_value *hosts = value->u.array.values[i];
        if(hosts->type != json_string) {
            anubis_err("%s: \"Hosts\": all should be a string\n", prefix);
            continue;
        }//end if
        
        char *ip = hosts->u.string.ptr;
        
        in_addr_t start_ip = 0, end_ip = 0;
        if(strchr(ip, '/')) {
            anubis_parse_ip_with_slash(prefix, ip, &start_ip, &end_ip);
            if(start_ip != 0 && end_ip != 0) {
                start_ip = htonl((ntohl(start_ip) + 1)); //skip network
                end_ip = htonl((ntohl(end_ip) - 1)); //skip broadcast
                if(start_ip > end_ip) {
                    anubis_err("%s: \"%s\" is not a valid IP address with slash\n", prefix, ip);
                    continue;
                }//end if
            }//end if
        }//end if
        else if(strchr(ip, '-')) {
            anubis_parse_ip_range(prefix, ip, &start_ip, &end_ip);
        }//end if
        else {
            anubis_parse_ip_address(prefix, name, hosts,
                                    &start_ip, sizeof(start_ip),
                                device, NULL);
            end_ip = start_ip;
        }//end else
        
        if(start_ip == 0 && end_ip == 0)
            continue;
        
        if(*set_value == NULL) {
            *set_value = (in_addr_t *)malloc(2 * sizeof(in_addr_t));
            if(!*set_value) {
                anubis_perror("calloc()");
                continue;
            }//end if fail
        }//end if
        else {
            in_addr_t *tmp = (in_addr_t *)realloc(*set_value,
                                                  sizeof(in_addr_t) * (*length + 2));
            if(!tmp) {
                anubis_perror("realloc()");
                continue;
            }//end if fail
            
            //assign
            *set_value = tmp;
        }//end else
        
        *(*set_value + *length) = start_ip;
        *length += 1;
        *(*set_value + *length) = end_ip;
        *length += 1;
        
    }//end for
    
    if(!*set_value)
        return;
    
    SET_REQUIRED(required);
}//end anubis_parse_host_list

void anubis_parse_ip_with_slash(const char *prefix, const char *ip_address, in_addr_t *start_ip, in_addr_t *end_ip) {
    *start_ip = *end_ip = 0;
    char *temp_ip = strdup(ip_address);
    char *tmp;
    int slash = 0;
    in_addr_t netmask = 0;
    if(!temp_ip) {
        anubis_perror("strdup()");
        return;
    }//end if
    
    if(!(tmp = strchr(temp_ip, '/'))) {
        anubis_err("%s: \"%s\" is not a valid IP address with slash\n", prefix, ip_address);
        goto BYE;
    }//end if
    
    //get slash
    *tmp = 0;
    tmp++;
    slash = atoi(tmp);
    
    if(slash < 0 || slash > 32) {
        anubis_err("%s: \"%s\" is not a valid IP address with slash\n", prefix, ip_address);
        goto BYE;
    }//end if
    
    in_addr_t mask = 1 << 31;
    for(int i = 0 ;i < slash ; i++) {
        netmask |= mask;
        mask >>= 1;
    }//end for
    netmask = htonl(netmask);
    
    *start_ip = anubis_ip_aton(temp_ip) & netmask; //ip & netmask = network
    *end_ip = *start_ip | ~netmask; //network | inverted netmask = broadcast
    
    anubis_verbose("%s: \"%s\", start: \"%s\", end: \"%s\"\n", prefix, ip_address, anubis_ip_ntoa(*start_ip), anubis_ip_ntoa(*end_ip));
    
BYE:
    free(temp_ip);
}//end anubis_parse_ip_with_slash

void anubis_parse_ip_range(const char *prefix, const char *ip_address, in_addr_t *start_ip, in_addr_t *end_ip) {
    *start_ip = *end_ip = 0;
    char *temp_ip = strdup(ip_address);
    char *tmp;
    
    if(!temp_ip) {
        anubis_perror("strdup()");
        return;
    }//end if
    
    if(!(tmp = strchr(temp_ip, '-'))) {
        anubis_err("%s: \"%s\" is not a valid IP address range\n", prefix, ip_address);
        goto BYE;
    }//end if
    
    //move to next
    *tmp = 0;
    tmp++;
    
    *start_ip = anubis_ip_aton(temp_ip);
    *end_ip = anubis_ip_aton(tmp);
    
    //if need swap
    if(ntohl(*start_ip) > ntohl(*end_ip)) {
        in_addr_t tmp = *start_ip;
        *start_ip = *end_ip;
        *end_ip = tmp;
    }//end if
    
    anubis_verbose("%s: \"%s\", start: \"%s\", end: \"%s\"\n",
                   prefix, ip_address, anubis_ip_ntoa(*start_ip), anubis_ip_ntoa(*end_ip));
    
BYE:
    free(temp_ip);
}//end anubis_parse_ip_range

void anubis_parse_json_string(char *json_string, unsigned long long length, anubis_model_callback_t *callback) {
    
    json_value *value = NULL;
    
    json_settings settings = {0};
    char errbuf[json_error_max] = {0};
    
    //enable comment
    settings.settings |= json_enable_comments;
    value = json_parse_ex(&settings, (json_char *)json_string, length, errbuf);
    
    if (!value) {
        anubis_err("%s\n", errbuf);
        return;
    }//end if
    
    if(value->type == json_array) {
        anubis_verbose("Start parsing socket\n");
        if(asynchronous)
            anubis_verbose("Asynchronous is enabled\n");
        for(int i = 0 ; i < value->u.array.length ; i++) {
            if(asynchronous) {
                pid_t pid = fork();
                if(pid == 0) {
                    anubis_parse_socket_type(value->u.array.values[i], i, callback);
                }//end if
                else if(pid == -1) {
                    anubis_perror("fork()");
                }//end if
                else {
                    continue;
                }
            }//end if
            else {
                anubis_parse_socket_type(value->u.array.values[i], i, callback);
            }//end else
        }//end for
        
        if (asynchronous) {
#ifdef __CYGWIN__
            wait(0);
#else
            wait(NULL);
#endif
        }
    }//end if
    else if(value->type == json_object) {
        anubis_verbose("Start parsing model\n");
        anubis_parse_model(value);
    }//end if
    else {
        anubis_err("Whole JSON should be an object or an array\n");
    }//end else
    
    //free
    json_value_free(value);
}//end anubis_parse_json_string

void anubis_parser(const char *filename) {
    
    FILE *fp = NULL;
    struct stat filestatus = {0};
    char *file_contents = NULL;
    unsigned long long file_size = 0;
    
    //get file state
    if (stat(filename, &filestatus) != 0) {
        anubis_perror("stat()");
        return;
    }//end if
    
    //get file size
    file_size = filestatus.st_size;
    file_contents = (char *)malloc(file_size);
    if (file_contents == NULL) {
        anubis_perror("malloc()");
        return;
    }//end if
    
    //open file
    fp = fopen(filename, "rt");
    if (!fp) {
        anubis_perror("fopen()");
        fclose(fp);
        free(file_contents);
        return;
    }//end if
    
    //get file content
    memset(file_contents, 0, file_size);
    if (fread(file_contents, file_size, 1, fp) != 1) {
        anubis_perror("fread()");
        fclose(fp);
        free(file_contents);
        return;
    }//end if
    fclose(fp);
    
#ifdef WIN32
    if(!anubis_init_winsock())
        return;
#endif
    
    //file information
    anubis_verbose("Filename: \"%s\"\n", filename);
    anubis_verbose("File size: %llu byte%s", file_size, file_size > 0 ? "s\n" : "\n");
    
    //parse with json string
    anubis_parse_json_string(file_contents, file_size, NULL);
    
    //free
    free(file_contents);
#ifdef WIN32
    WSACleanup();
#endif
}//end anubis_parser

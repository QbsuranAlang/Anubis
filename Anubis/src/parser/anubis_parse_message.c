//
//  anubis_parse_message.c
//  Anubis
//
//  Created by TUTU on 2016/6/23.
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

static void anubis_parse_message_hdr(char *prefix, json_value *json, anubis_message_hdr *message_hdr);

void anubis_parse_ssdp_hdr(json_value *json, anubis_message_hdr *ssdp_hdr) {
    
    anubis_parse_message_hdr("SSDP", json, ssdp_hdr);
    
}//end anubis_parse_ssdp_hdr

void anubis_parse_http_hdr(json_value *json, anubis_message_hdr *http_hdr) {
    
    anubis_parse_message_hdr("HTTP", json, http_hdr);
    
}//end anubis_parse_http_hdr

static void anubis_parse_message_hdr(char *prefix, json_value *json, anubis_message_hdr *message_hdr) {
    
    CHECK_OBJECT_TYPE(json, prefix, prefix);
    int request = 0;
    int response = 0;
    int required_field = 0;
    char prefix_request[ANUBIS_BUFFER_SIZE] = {0};
    char prefix_response[ANUBIS_BUFFER_SIZE] = {0};
    char prefix_field[ANUBIS_BUFFER_SIZE] = {0};
    
    snprintf(prefix_request, sizeof(prefix_request), "%s: \"Request\"", prefix);
    snprintf(prefix_response, sizeof(prefix_response), "%s: \"Response\"", prefix);
    snprintf(prefix_field, sizeof(prefix_field), "%s: \"Field\"", prefix);
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Request")) {
            request = 1;
            if(value->type != json_object) {
                anubis_err("%s: \"Request\" should be an object\n", prefix);
                continue;
            }//end if
            
            int required_method = 0;
            int required_url = 0;
            message_hdr->type = ANUBIS_MESSAGE_REQUEST;
            
            for(int j = 0 ; j < value->u.object.length ; j++) {
                json_char *name = value->u.object.values[j].name;
                json_value *field = value->u.object.values[j].value;
                
                if(!strcasecmp(name, "Method")) {
                    anubis_parse_string(prefix_request, name, field, &message_hdr->method, &required_method);
                }
                else if(!strcasecmp(name, "URL")) {
                    anubis_parse_string(prefix_request, name, field, &message_hdr->url, &required_url);
                }
                else if(!strcasecmp(name, "Version")) {
                    anubis_parse_string(prefix_request, name, field, &message_hdr->version, NULL);
                }//end if
                else {
                    anubis_err("%s: \"%s\" unknown field\n", prefix_request, name);
                }//end else
            }//end for
            
            CHECK_REQUIREMENT(required_method, prefix_request, "Method");
            CHECK_REQUIREMENT(required_url, prefix_request, "URL");
        }//end if
        else if(!strcasecmp(name, "Response")) {
            response = 1;
            if(value->type != json_object) {
                anubis_err("%s: \"Response\" should be an object\n", prefix);
                continue;
            }//end if
            
            int required_code = 0;
            int required_phrase = 0;
            message_hdr->type = ANUBIS_MESSAGE_RESPONSE;
            
            for(int j = 0 ; j < value->u.object.length ; j++) {
                json_char *name = value->u.object.values[j].name;
                json_value *field = value->u.object.values[j].value;
                
                if(!strcasecmp(name, "Version")) {
                    anubis_parse_string(prefix_response, name, field, &message_hdr->version, NULL);
                }//end if
                else if(!strcasecmp(name, "Status Code")) {
                    anubis_parse_4bytes_integer(prefix_response, name, field, &message_hdr->status_code, &required_code);
                }//end if
                else if(!strcasecmp(name, "Phrase")) {
                    anubis_parse_string(prefix_response, name, field, &message_hdr->phrase, &required_phrase);
                }//end if
                else {
                    anubis_err("%s: \"%s\" unknown field\n", prefix_response, name);
                }//end else
                
                if(required_code && !required_phrase) {
                    message_hdr->phrase = (char *)anubis_message_status_code_to_phrase(message_hdr->status_code);
                }//end if code only
                else if(required_phrase && !required_code) {
                    message_hdr->status_code = anubis_message_phrase_to_status_code(message_hdr->phrase);
                }//end if phrase
                
            }//end for
        }//end if
        else if(!strcasecmp(name, "Field")) {
            if(value->type != json_object) {
                anubis_err("%s: \"Field\" should be an object\n", prefix);
                continue;
            }//end if
            required_field = 1;
            
            json_value *keys = NULL;
            json_value *values = NULL;
            
            for(int j = 0; j < value->u.object.length ; j++) {
                json_char *name = value->u.object.values[j].name;
                json_value *array = value->u.object.values[j].value;
                
                if(!strcasecmp(name, "Keys")) {
                    keys = array;
                }//end if
                else if(!strcasecmp(name, "Values")) {
                    values = array;
                }//end if
                else {
                    anubis_err("%s: \"%s\" unknown field\n", prefix_field, name);
                }//end else
            }//end for
            
            
            //check
            CHECK_REQUIREMENT(keys, prefix_field, "Keys");
            CHECK_REQUIREMENT(values, prefix_field, "Values");
            if(!keys || !values)
                continue;
            
            if(keys->type != json_array) {
                anubis_err("%s: \"Fields\" should be an array\n", prefix_field);
                continue;
            }//end if
            
            if(values->type != json_array) {
                anubis_err("%s: \"Values\" should be an array\n", prefix_field);
                continue;
            }//end if
            
            //parse fields
            message_hdr->keys = (char **)malloc(sizeof(char *) * keys->u.array.length);
            message_hdr->keys_lines = keys->u.array.length;
            if(!message_hdr->keys) {
                anubis_perror("malloc()");
                continue;
            }//end if
            for(int j = 0 ; j < keys->u.array.length ; j++) {
                if(keys->u.array.values[j]->type != json_string) {
                    anubis_err("%s: \"Fields\": all should be a string\n", prefix_field);
                    continue;
                }//end if
                message_hdr->keys[j] = keys->u.array.values[j]->u.string.ptr;
            }//end for
            
            //parse values
            message_hdr->values = (char **)malloc(sizeof(char *) * values->u.array.length);
            message_hdr->values_lines = values->u.array.length;
            if(!message_hdr->values) {
                anubis_perror("malloc()");
                continue;
            }//end if
            for(int j = 0 ; j < values->u.array.length ; j++) {
                if(values->u.array.values[j]->type != json_string) {
                    anubis_err("%s: \"Values\": all should be a string\n", prefix_field);
                    continue;
                }//end if
                message_hdr->values[j] = values->u.array.values[j]->u.string.ptr;
            }//end for
        }//end if message
        else {
            anubis_err("%s: \"%s\" unknown field\n", prefix, name);
        }//end else
    }//end for
    
    if(request && response)
        anubis_err("%s: \"Request\" and \"Response\" should not be appear at the same time\n", prefix);
    if(!request && !response)
        anubis_err("%s: \"Request\" or \"Response\" should be appear one of them\n", prefix);
    CHECK_REQUIREMENT(required_field, prefix, "Field");
    if(message_hdr->keys_lines != message_hdr->values_lines)
        anubis_err("%s: \"Field\": \"Keys\" and \"Values\" count should be the same\n", prefix);
    
    int status_line_length = 0;
    if(message_hdr->type == ANUBIS_MESSAGE_REQUEST) {
        if(message_hdr->method)
            status_line_length += strlen(message_hdr->method);
        if(message_hdr->url)
            status_line_length += 1 + strlen(message_hdr->url);
        if(message_hdr->version)
            status_line_length += 1 + strlen(message_hdr->version);
        status_line_length += strlen("\r\n");
        
        message_hdr->status_line = (char *)malloc(status_line_length + 1);
        if(!message_hdr->status_line) {
            anubis_perror("malloc()");
            return;
        }//end if
        
        memset(message_hdr->status_line, 0, status_line_length + 1);
        snprintf(message_hdr->status_line, status_line_length + 1, "%s %s %s\r\n",
                 message_hdr->method ? message_hdr->method : "",
                 message_hdr->url ? message_hdr->url : "",
                 message_hdr->version ? message_hdr->version : "");
        message_hdr->length += status_line_length;
    }//end if
    else if (message_hdr->type == ANUBIS_MESSAGE_RESPONSE) {
        if(message_hdr->version)
            status_line_length += strlen(message_hdr->version);
        char code[ANUBIS_BUFFER_SIZE] = {0};
        snprintf(code, sizeof(code), "%d", message_hdr->status_code);
        status_line_length += 1 + strlen(code);
        if(message_hdr->phrase)
            status_line_length += 1 + strlen(message_hdr->phrase);
        status_line_length += strlen("\r\n");
        
        message_hdr->status_line = (char *)malloc(status_line_length + 1);
        if(!message_hdr->status_line) {
            anubis_perror("malloc()");
            return;
        }//end if
        
        memset(message_hdr->status_line, 0, status_line_length + 1);
        snprintf(message_hdr->status_line, status_line_length + 1, "%s %s %s\r\n",
                 message_hdr->version ? message_hdr->version : "",
                 code,
                 message_hdr->phrase ? message_hdr->phrase : "");
        message_hdr->length += status_line_length;
    }//end if response
    
    //count messages total length
    int message_line_length = 0;
    for(int i = 0 ; i < MIN(message_hdr->keys_lines, message_hdr->values_lines) ; i++) {
        char *field = message_hdr->keys[i];
        char *value = message_hdr->values[i];
        message_line_length += (int)(strlen(field) + strlen(": ") + strlen(value) + strlen("\r\n"));
    }//end for
    
    message_line_length += (int)strlen("\r\n");
    
    message_hdr->fields = (char *)malloc(message_line_length + 1);
    if(!message_hdr->fields) {
        anubis_perror("malloc()");
        return;
    }//end if
    
    memset(message_hdr->fields, 0, message_line_length + 1);
    for(int i = 0 ; i < MIN(message_hdr->keys_lines, message_hdr->values_lines) ; i++) {
        char *field = message_hdr->keys[i];
        char *value = message_hdr->values[i];
        snprintf(message_hdr->fields, message_line_length + 1, "%s%s: %s\r\n", message_hdr->fields, field, value);
    }//end for
    strlcat(message_hdr->fields, "\r\n", message_line_length + 1);
    message_hdr->length += message_line_length;
    
    //all data
    message_hdr->data = (char *)malloc(message_hdr->length + 1);
    if(!message_hdr->data) {
        anubis_perror("malloc()");
        return;
    }//end if
    
    memset(message_hdr->data, 0, message_hdr->length + 1);
    memmove(message_hdr->data, message_hdr->status_line, status_line_length);
    memmove(message_hdr->data + status_line_length, message_hdr->fields, message_line_length);
}//end anubis_parse_message_hdr
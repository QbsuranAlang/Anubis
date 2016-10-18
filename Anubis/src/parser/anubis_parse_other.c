//
//  anubis_parse_other.c
//  Anubis
//
//  Created by TUTU on 2016/6/23.
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

void anubis_parse_raw_data(json_value *json, anubis_packet_raw_data_t *raw_data) {
    CHECK_OBJECT_TYPE(json, "Raw Data", "Raw Data");
    
    int required_data = 0;
    u_int16_t length = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Data")) {
            anubis_parse_string("Raw Data", name, value, (char **)&raw_data->data, &required_data);
            if(!raw_data->data)
                continue;
            length = value->u.string.length;
        }//end if
        else if(!strcasecmp(name, "Data length")) {
            anubis_parse_2bytes_integer("Raw Data", name, value,
                                        &raw_data->data_length, NULL);
        }//end if
        else {
            anubis_err("Raw Data: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    if(raw_data->data_length == 0)
        raw_data->data_length = length;
    
    CHECK_REQUIREMENT(required_data, "Raw Data", "Data");
}//end anubis_parse_raw_data

void anubis_parse_payload(json_value *json, anubis_packet_raw_data_t *payload) {
    
    CHECK_OBJECT_TYPE(json, "Payload", "Payload");
    
    int required_payload = 0;
    u_int16_t length = 0;
    
    for(int i = 0 ; i < json->u.object.length ;i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(!strcasecmp(name, "Payload")) {
            anubis_parse_string("Raw Data", name, value, (char **)&payload->data, &required_payload);
            if(!payload->data)
                continue;
            length = value->u.string.length;
        }//end if
        else if(!strcasecmp(name, "Payload length")) {
            anubis_parse_2bytes_integer("Payload", name, value,
                                        &payload->data_length, NULL);
        }//end if
        else {
            anubis_err("Payload: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    if(payload->data_length == 0)
        payload->data_length = length;
    
    CHECK_REQUIREMENT(required_payload, "Payload", "Payload");
}//end anubis_parse_payload

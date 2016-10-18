//
//  anubis_model.c
//  Anubis
//
//  Created by TUTU on 2016/6/25.
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

void anubis_parse_model(json_value *json) {
    int required_model = 0;
    anubis_model_t model = {0};
    json_value *model_json_value = NULL;
    
    memset(&model, 0, sizeof(model));
    
    //get model name first
    for(int i = 0 ; i < json->u.object.length ; i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(value->type != json_object) {
            continue;
        }//end if
        
        if(!strcasecmp(name, "Option")) {
            for(int j = 0 ; j < value->u.object.length ; j++) {
                json_char *name = value->u.object.values[j].name;
                json_value *option_value = value->u.object.values[j].value;
                if(!strcasecmp(name, "Model")) {
                    anubis_parse_string("Model", name, option_value, &model.model_name, &required_model);
                    if(!model.model_name)
                        continue;
                    model.model_name = strdup(model.model_name);
                    if(!model.model_name) {
                        anubis_perror("strdup()");
                        continue;
                    }//end if
                }//end if
                break;
            }//end for
        }//end if
        if(model.model_name)
            break;
    }//end for
    
    //check model
    CHECK_REQUIREMENT(required_model, "Model", "Model");
    if(!required_model) {
        anubis_free_model(&model);
        return;
    }
    
    //get default model structure
    if(!strcasecmp(model.model_name, "arping")) {
        anubis_default_model_arping(&model);
    }//end if arping
    else if(!strcasecmp(model.model_name, "arpoison")) {
        anubis_default_model_arpoison(&model);
    }//end ifarpoison
    else {
        anubis_err("Model: \"%s\" unknown model\n", model.model_name);
        anubis_free_model(&model);
        return;
    }//end else
    
    //get base parameter
    for(int i = 0 ; i < json->u.object.length ; i++) {
        json_char *name = json->u.object.values[i].name;
        json_value *value = json->u.object.values[i].value;
        
        if(value->type != json_object) {
            anubis_err("Each object should be an object\n");
            continue;
        }//end if
        
        if(!strcasecmp(name, "Option")) {
            for(int j = 0 ; j < value->u.object.length ; j++) {
                json_char *name = value->u.object.values[j].name;
                json_value *option_value = value->u.object.values[j].value;
                if(!strcasecmp(name, "Model")) {
                }//end if
                else if(!strcasecmp(name, "_comment")) {
                    if(option_value->type == json_string && option_value->u.string.length == 0)
                        continue;
                    anubis_parse_string("Model", name, option_value, &model.comment, NULL);
                    if(!model.comment)
                        continue;
                    model.comment = strdup(model.comment);
                    if(!model.comment) {
                        anubis_perror("strdup()");
                        continue;
                    }//end if
                }//end if comment
                else if(!strcasecmp(name, "Device")) {
                    if(model.device)
                        free(model.device);
                    model.device = NULL;
                    anubis_parse_string("Model", name, option_value, &model.device, NULL);
                    if(!model.device)
                        continue;
                    model.device = strdup(model.device);
                    if(!model.device) {
                        anubis_perror("strdup()");
                        continue;
                    }//end if
                }//end if device
                else if(!strcasecmp(name, "Save configuration to file")) {
                    anubis_parse_string("Model", name, option_value, &model.save_config, NULL);
                    if(!model.save_config)
                        continue;
                    model.save_config = strdup(model.save_config);
                    if(!model.save_config) {
                        anubis_perror("strdup()");
                        continue;
                    }//end if
                }//end if device
                else if(!strcasecmp(name, "Infinite loop")) {
                    anubis_parse_boolean("Model", name, option_value, &model.infinite_loop, NULL);
                }//end if
                else if(!strcasecmp(name, "Interval")) {
                    anubis_parse_4bytes_integer("Model", name, option_value, &model.interval, NULL);
                }//end if
                else if(!strcasecmp(name, "Amount")) {
                    anubis_parse_4bytes_integer("Model", name, option_value, &model.amount, NULL);
                }//end if
                else if(!strcasecmp(name, "Dump send packet")) {
                    anubis_parse_boolean("Model", name, option_value, &model.dump_send, NULL);
                }//end if
                else if(!strcasecmp(name, "Filter")) {
                    if(option_value->type != json_string) {
                        anubis_err("%s: \"%s\" should be a string\n", "arping", name);
                        continue;
                    }//end if
                    model.filter = option_value->u.string.ptr;
                    model.filter = strdup(model.filter);
                    if(!model.filter) {
                        anubis_perror("strdup()");
                        continue;
                    }//end if
                }//end if
                else if(!strcasecmp(name, "Receive Timeout")) {
                    anubis_parse_4bytes_integer("Model", name, option_value, &model.recv_timeout, NULL);
                }//end if
                else if(!strcasecmp(name, "Dump receive packet")) {
                    anubis_parse_boolean("Model", name, option_value, &model.dump_recv, NULL);
                }//end if
                else {
                    anubis_err("Model: \"%s\" unknown field\n", name);
                }//end else
            }//end for
        }//end if option
        else if(!strcasecmp(name, "Model")) {
            model_json_value = value;
        }//end else
        else {
            anubis_err("Model: \"%s\" unknown field\n", name);
        }//end else
    }//end for
    
    //check requirement
    CHECK_REQUIREMENT(model_json_value, "Model", "Model");
    
    if(!model_json_value) {
        anubis_free_model(&model);
        return;
    }//end if
    
    //start parse each model parameter
    anubis_verbose("Start parsing \"%s\" model\n", model.model_name);
    
    if(!strcasecmp(model.model_name, "arping")) {
        anubis_parse_model_arping(model_json_value, &model);
    }//end if arping
    else if(!strcasecmp(model.model_name, "arpoison")) {
        anubis_parse_model_arpoison(model_json_value, &model);
    }//end ifarpoison
    else {
        anubis_err("Model: \"%s\" unknown model\n", model.model_name);
    }//end else
    
    //free
    anubis_free_model(&model);
    
}//end anubis_parse_model

void anubis_free_model(anubis_model_t *model) {
    if(model->comment)
        free(model->comment);
    if(model->device)
        free(model->device);
    if(model->model_name)
        free(model->model_name);
    if(model->save_config)
        free(model->save_config);
    if(model->filter)
        free(model->filter);
    if(model->pcap_handle)
        pcap_close(model->pcap_handle);
    
    model->comment = NULL;
    model->device = NULL;
    model->model_name = NULL;
    model->save_config = NULL;
    model->filter = NULL;
    model->pcap_handle = NULL;
}//end anubis_free_model

pcap_t *anubis_open_pcap(char *device, int to_ms, char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    
    /*zero will block.*/
    if(to_ms == 0)
        to_ms = 1;
    
    pcap_t *handle = pcap_open_live(device, 65535, 1, to_ms, errbuf);
    if(!handle) {
        anubis_err("pcap_open_live(): %s\n", errbuf);
        return NULL;
    }//end if
    
    if(filter) {
        anubis_verbose("Applying filter: \"%s\"\n", filter);
        
        bpf_u_int32 net, mask;
        struct bpf_program fcode;
        
        if(-1 == pcap_lookupnet(device, &net, &mask, errbuf)) {
            anubis_err("pcap_lookupnet(): %s\n", errbuf);
            pcap_close(handle);
            return NULL;
        }//end if
        
        //compile filter
        if(-1 == pcap_compile(handle, &fcode, filter, 1, mask)) {
            anubis_err("pcap_compile(): %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return NULL;
        }//end if
        
        //set filter
        if(-1 == pcap_setfilter(handle, &fcode)) {
            anubis_err("pcap_setfilter(): %s\n", pcap_geterr(handle));
            pcap_freecode(&fcode);
            pcap_close(handle);
            return NULL;
        }//end if
        
        //free code
        pcap_freecode(&fcode);
    }//end if need filter
    
    return handle;
}//end anubis_open_pcap

void anubis_save_to_file(const char *filename, const char *json) {
    anubis_verbose("Saving JSON configuration to file: \"%s\"\n", filename);
    FILE *fp = fopen(filename, "w+");
    if(!fp) {
        anubis_perror("fopen()");
        return;
    }//end if
    else {
        fprintf(fp, "%s", json + strspn(json, "\n")); //skip first newline
        fflush(fp);
        fclose(fp);
    }//end else
    anubis_verbose("Saved to file: \"%s\"\n", filename);
}//end anubis_save_to_file

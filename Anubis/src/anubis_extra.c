//
//  anubis_extra.c
//  Anubis
//
//  Created by 聲華 陳 on 2016/4/12.
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

void anubis_wait_microsecond(u_int32_t microsecond) {
    anubis_verbose("Sleep for %d microsecond%s", microsecond, microsecond ? "s\n" : "\n");
    struct timeval delay = { microsecond / 1000000, microsecond % 1000000 };
    select(0, NULL, NULL, NULL, &delay);
    
    /*
     //sometimes don't work
     unsigned long nsec = microsecond * 1000;
     struct timespec delay = { nsec / 1000000000, nsec % 1000000000 };
     pselect(0, NULL, NULL, NULL, &delay, NULL);
     */
    
}//end anubis_wait_microsecond

void anubis_fragment_offset(int data_len, int mtu, int ip_hl) {
    
    if(ip_hl < 20 || ip_hl > 60 || ip_hl % 4)
        anubis_err("anubis_fragment_offset(): \"%d\" is not a valid IP header length\n", ip_hl);
    
    anubis_out("IP paylaod length: %d, MTU: %d, IP header length: %d\n", data_len, mtu, ip_hl);
    int round = 1;
    int i = 0;
    do {
        if(i + (mtu - ip_hl) > data_len) { //final one
            anubis_out("No.%d: Total length: %d, Flags: 0, Fragment offset: %d, Fragment offset in packet: %d\n",
                       round++, data_len - i + ip_hl, i, i >> 3);
        }
        else {
            anubis_out("No.%d: Total length: %d, Flags: IP_MF, Fragment offset: %d, Fragment offset in packet: %d\n",
                       round++, mtu, i, i >> 3);
        }
        i += mtu - ip_hl;
    }
    while(i < data_len);
    
}//end anubis_fragment_offset

void anubis_list_devices(char *device) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
    int found = 0;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        anubis_err("%s\n", errbuf);
        return;
    }
    
    for(d = alldevs; d ; d = d->next) {
        pcap_addr_t *a;
        char ntop_buf[INET6_ADDRSTRLEN];
        
        if(device && strcmp(device, d->name))
            continue;
        if(device)
            found = 1;
        
#ifdef __CYGWIN__
	    char *name = d->name;
	    char *tmp = NULL;
	    if (!(tmp = strstr(name, "{")))
		    tmp = name;
	    anubis_out("Name: %s%s\n", tmp, (d->flags & PCAP_IF_LOOPBACK) ? " [Loopback]" : "");
#else
	    anubis_out("Name: %s%s\n", d->name, (d->flags & PCAP_IF_LOOPBACK) ? " [Loopback]" : "");
#endif
        
        if (d->description)
            anubis_out("\tDescription: %s\n",d->description);
        
        //print address
        for(a = d->addresses ; a ; a = a->next) {
            switch(a->addr->sa_family) {
                case AF_INET:
                    anubis_out("\tAddress Family: AF_INET\n");
                    if (a->addr)
                        anubis_out("\t\tAddress: %s\n", anubis_ip_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr.s_addr));
                    if (a->netmask)
                        anubis_out("\t\tNetmask: %s\n", anubis_ip_ntoa(((struct sockaddr_in *)(a->netmask))->sin_addr.s_addr));
                    if (a->broadaddr)
                        anubis_out("\t\tBroadcast Address: %s\n", anubis_ip_ntoa(((struct sockaddr_in *)(a->broadaddr))->sin_addr.s_addr));
                    if (a->dstaddr)
                        anubis_out("\t\tDestination Address: %s\n", anubis_ip_ntoa(((struct sockaddr_in *)(a->dstaddr))->sin_addr.s_addr));
                    break;
                case AF_INET6:
                    anubis_out("\tAddress Family: AF_INET6\n");
                    if (a->addr)
                        anubis_out("\t\tAddress: %s\n",
                                   inet_ntop(AF_INET6,
                                             ((struct sockaddr_in6 *)(a->addr))->sin6_addr.s6_addr,
                                             ntop_buf, sizeof ntop_buf));
                    if (a->netmask)
                        anubis_out("\t\tNetmask: %s\n",
                                   inet_ntop(AF_INET6,
                                             ((struct sockaddr_in6 *)(a->netmask))->sin6_addr.s6_addr,
                                             ntop_buf, sizeof ntop_buf));
                    if (a->broadaddr)
                        anubis_out("\t\tBroadcast Address: %s\n",
                                   inet_ntop(AF_INET6,
                                             ((struct sockaddr_in6 *)(a->broadaddr))->sin6_addr.s6_addr,
                                             ntop_buf, sizeof ntop_buf));
                    if (a->dstaddr)
                        anubis_out("\t\tDestination Address: %s\n",
                                   inet_ntop(AF_INET6,
                                             ((struct sockaddr_in6 *)(a->dstaddr))->sin6_addr.s6_addr,
                                             ntop_buf, sizeof ntop_buf));
                    break;
                    
#ifndef __CYGWIN__
                case AF_LINK: {
                    if(a->addr) {
#ifndef __linux
						struct sockaddr_dl *sdl = (struct sockaddr_dl *)a->addr;
						if (sdl->sdl_alen == 6) {
							anubis_out("\tAddress Family: AF_LINK\n");

							anubis_out("\t\tAddress: %s\n", anubis_mac_ntoa((u_int8_t *)(sdl->sdl_data + sdl->sdl_nlen)));
						}
#else
						struct sockaddr_ll *sll = (struct sockaddr_ll *)a->addr;
						if (sll->sll_halen == 6) {
							anubis_out("\tAddress Family: AF_PACKET\n");
							anubis_out("\t\tAddress: %s\n", anubis_mac_ntoa((u_int8_t *)(sll->sll_addr)));
						}
#endif
                    }
                }//end case AF_LINK
                    break;
#endif
                default:
                    anubis_out("\tAddress Family: Unknown (%d)\n", a->addr->sa_family);
                    break;
            }//end
        }//end for address

		//windows mac address
#ifdef __CYGWIN__
		char errbuf2[LIBNET_ERRBUF_SIZE] = { 0 };
		libnet_t *libnet_handle = libnet_init(LIBNET_RAW4, d->name, errbuf2);
		if (!libnet_handle) {
			anubis_err("%s\n", errbuf2);
		}
		else {
			struct libnet_ether_addr *hwaddr = libnet_get_hwaddr(libnet_handle);
			if (!hwaddr) {
				anubis_err("%s\n", libnet_geterror(libnet_handle));
			}
			else {
				anubis_out("\tAddress Family: LINK\n");
				anubis_out("\t\tAddress: %s\n", anubis_mac_ntoa(hwaddr->ether_addr_octet));
			}
			libnet_destroy(libnet_handle);
		}
#endif

        //print data link types
        pcap_t *pcap_handle = pcap_open_live(d->name, 1, 0, 1, errbuf);
        if(!pcap_handle) {
            anubis_err("%s\n", errbuf);
        }
        else {
            int *dlts;
            int default_type = pcap_datalink(pcap_handle);
            int len = pcap_list_datalinks(pcap_handle, &dlts);
            if(!dlts) {
                anubis_err("%s\n", pcap_geterr(pcap_handle));
            }
            else {
                if(len > 0) {
                    anubis_out("\tData-link types:\n");
                    for(int i = 0 ; i < len ; i++) {
                        anubis_out("\t\t%d. ", i + 1);
                        
                        if(pcap_datalink_val_to_name(dlts[i])) {
							fprintf(out_stream, "%s(%s)",
								pcap_datalink_val_to_name(dlts[i]), pcap_datalink_val_to_description(dlts[i]));
                        }
                        else {
							fprintf(out_stream, "Unknown: %d", dlts[i]);
                        }
                        
						if (dlts[i] == default_type)
							fprintf(out_stream, " [Default]");

						fprintf(out_stream, "\n");
                    }//end for
                }//end if
                
                //free data link types list
				pcap_free_datalinks(dlts);
            }//end else
            
            pcap_close(pcap_handle);
        }//end if open live
        //anubis_out("\n");
    }//end for devices
    
    pcap_freealldevs(alldevs);
    
    if(device && !found) {
        anubis_err("anubis_list_devices(): \"%s\" is not found\n", device);
    }//end if device name is given but not found
    
}//end anubis_list_devices
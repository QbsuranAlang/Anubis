//
//  anubis_structure.h
//  Anubis
//
//  Created by 聲華 陳 on 2016/3/31.
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


#ifndef anubis_structure_h
#define anubis_structure_h

#ifndef WIN32
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
//#include <netinet/ip_icmp.h>
#else

#endif

typedef enum {
    anubis_data_link_socket = 1,
    anubis_network_socket,
    anubis_transport_socket,
    anubis_application_socket
} anubis_socket_type;

typedef enum {
    anubis_ethernet = 1,
    anubis_arp,
    anubis_wol,
    anubis_ip,
    anubis_ip_option,
    anubis_udp,
    anubis_tcp,
    anubis_tcp_option,
    anubis_icmp,
    anubis_rip,
    anubis_ssdp,
    anubis_http,
    anubis_dhcp,
    anubis_dhcp_option,
    
    anubis_raw_data,
    anubis_payload
} anubis_socket_protocol;

/*Raw Data structure*/
typedef struct {
    u_int8_t *data;
    u_int16_t data_length;
} anubis_packet_raw_data_t;

/*Options structure*/
typedef struct {
    u_int8_t *options;
    u_int16_t options_length;
} anubis_options_t;

/*Ethernet ARP structure*/
typedef struct {
    struct libnet_arp_hdr ea_hdr;
    u_int8_t	arp_sha[ETHER_ADDR_LEN];	/* sender hardware address */
    u_int8_t	arp_spa[4];	/* sender protocol address */
    u_int8_t	arp_tha[ETHER_ADDR_LEN];	/* target hardware address */
    u_int8_t	arp_tpa[4];	/* target protocol address */
    
#ifndef arp_hrd
#define	arp_hrd	ea_hdr.ar_hrd
#endif
#ifndef arp_pro
#define	arp_pro	ea_hdr.ar_pro
#endif
#ifndef arp_hln
#define	arp_hln	ea_hdr.ar_hln
#endif
#ifndef arp_pln
#define	arp_pln	ea_hdr.ar_pln
#endif
#ifndef arp_op
#define	arp_op	ea_hdr.ar_op
#endif
} anubis_ether_arp_t;
#define ANUBIS_ETH_ARP_H 28

/*RIP Route Table Entry*/
typedef struct {
    uint16_t rip_af;         /* Address family */
    uint16_t rip_rt;         /* Zero (v1) or Route Tag (v2) */
    in_addr_t rip_addr;        /* IP address */
    in_addr_t rip_mask;        /* Zero (v1) or Subnet Mask (v2) */
    in_addr_t rip_next_hop;    /* Zero (v1) or Next hop IP address (v2) */
    u_int32_t rip_metric;      /* Metric */
} anubis_rte_t;
#define ANUBIS_RTE_H 20 /*20 bytes*/

/*ICMP structure*/
typedef struct {
    u_int8_t	icmp_type;		/* type of message, see below */
    u_int8_t	icmp_code;		/* type sub code */
    u_int16_t	icmp_cksum;		/* ones complement cksum of struct */
    union {
        u_int8_t ih_pptr;			/* ICMP_PARAMPROB */
        struct in_addr ih_gwaddr;	/* ICMP_REDIRECT */
        struct ih_idseq {
            u_int16_t	icd_id;
            u_int16_t	icd_seq;
        } ih_idseq;
        int ih_void;
        
        /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
        struct ih_pmtu {
            u_int16_t ipm_void;
            u_int16_t ipm_nextmtu;
        } ih_pmtu;
        
        struct ih_rtradv {
            u_int8_t irt_num_addrs;
            u_int8_t irt_wpa;
            u_int16_t irt_lifetime;
        } ih_rtradv;
    } icmp_hun;
#ifndef icmp_pptr
#define	icmp_pptr	icmp_hun.ih_pptr
#endif
#undef icmp_gwaddr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#undef icmp_id
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#undef icmp_seq
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#ifndef icmp_void
#define	icmp_void	icmp_hun.ih_void
#endif
#ifndef icmp_pmvoid
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#endif
#ifndef icmp_nextmtu
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
#endif
#ifndef icmp_num_addrs
#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
#endif
#ifndef icmp_wpa
#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
#endif
#ifndef icmp_lifetime
#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime
#endif
    union {
        struct id_ts {
            u_int32_t its_otime;
            u_int32_t its_rtime;
            u_int32_t its_ttime;
        } id_ts;
        struct id_ip  {
            struct libnet_ipv4_hdr idi_ip;
            /* options and then 64 bits of data */
        } id_ip;
        
        /*
         * Internal of an ICMP Router Advertisement
         */
        struct icmp_ra_addr {
            u_int32_t ira_addr;
            u_int32_t ira_preference;
        } id_radv;
        u_int32_t id_mask;
        char	id_data[1];
    } icmp_dun;
#ifndef icmp_otime
#define	icmp_otime	icmp_dun.id_ts.its_otime
#endif
#ifndef icmp_rtime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#endif
#ifndef icmp_ttime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#endif
#ifndef icmp_ip
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#endif
#ifndef icmp_radv
#define	icmp_radv	icmp_dun.id_radv
#endif
#ifndef icmp_mask
#define	icmp_mask	icmp_dun.id_mask
#endif
#undef icmp_data
#define	icmp_data	icmp_dun.id_data
} anubis_icmp_t;

/*Wake-ON-LAN structure*/
#define ANUBIS_WOL_H 108
typedef struct {
    u_int8_t sync_stream[6];
    u_int8_t mac_address[16][6];
    u_int8_t password[6];
} anubis_wol_hdr;
#define ANUBIS_WOL_H 108

/*Message request structure*/
typedef struct {
    
    int type; //is request or response
#define ANUBIS_MESSAGE_REQUEST 1
#define ANUBIS_MESSAGE_RESPONSE 2
    
    /*status line detail*/
    char *method;
    char *url;
    char *version;
    u_int32_t status_code;
    char *phrase;
    
    /*fields lines detail*/
    int keys_lines;
    char **keys;
    int values_lines;
    char **values;
    
    /*status line and fields lines*/
    char *status_line;
    char *fields;
    
    /*whole data*/
    char *data;
    int length;
} anubis_message_hdr;

/*protocol headers*/
typedef struct {
    anubis_socket_protocol protocol_type;
    union {
        struct libnet_ethernet_hdr ethernet;
        anubis_ether_arp_t arp;
        anubis_wol_hdr wol;
        struct libnet_ipv4_hdr ip;
        anubis_options_t ip_options;
        struct libnet_udp_hdr udp;
        struct libnet_tcp_hdr tcp;
        anubis_options_t tcp_options;
        anubis_icmp_t icmp;
        anubis_packet_raw_data_t rip;
        anubis_message_hdr ssdp;
        anubis_message_hdr http;
        struct libnet_dhcpv4_hdr dhcp;
        anubis_options_t dhcp_options;
        anubis_packet_raw_data_t raw_data;
        
        anubis_packet_raw_data_t payload;
    } u;
} anubis_protocol_t;

/*packet sequence*/
typedef struct {
    anubis_protocol_t *protocols;
    int layers;
    int out_going;
    int infinite_loop;
    u_int32_t interval;
    u_int32_t amount;
    int dump_send;
    int dump_recv;
    u_int32_t send_timeout;
    u_int16_t send_length;
    u_int32_t recv_timeout;
    int interactive;
    int read_until_timeout;
    char *input_filename;
    char *output_filename;
} anubis_packet_t;

/*socket config structure*/
typedef struct {
    char *device;
    char *comment;
    int index;
    int infinite_loop;
    u_int32_t interval;
    u_int32_t amount;
    anubis_socket_type socket_type;
    unsigned int sequence_length;
    json_value **sequence_data;
    in_addr_t dst_ip;
    u_int16_t dst_port;
    u_int16_t src_port;
    in_addr_t *muliticast_groups;
    int muliticast_groups_length;
    int type; /*SOCK_DGRAM, SOCK_STREAM*/
    int protocol;
    u_int32_t send_timeout;
    u_int32_t recv_timeout;
    
#define ANUBIS_ROLE_SERVER 1
#define ANUBIS_ROLE_CLIENT 2
    int role;
    
    int security_socket;
    char *sslMethod;
    int asynchronous;
    u_int16_t max_connection;
    char *certificate_file;
    char *private_key_file;
    int certificate_information;
    
    anubis_packet_t *packets;
    int packets_count;
} anubis_t;

#endif /* anubis_structure_h */

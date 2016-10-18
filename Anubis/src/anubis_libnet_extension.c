//
//  anubis_libnet_extension.c
//  Anubis
//
//  Created by TUTU on 2016/4/6.
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

/* some common cruft for completing ICMP error packets */
#define LIBNET_BUILD_ICMP_ERR_FINISH(len)                                    \
do                                                                           \
{                                                                            \
    n = libnet_pblock_append(l, p, (uint8_t *)&icmp_hdr, len);              \
    if (n == -1)                                                             \
    {                                                                        \
        goto bad;                                                            \
    }                                                                        \
                                                                             \
    if (payload_s && !payload)                                               \
    {                                                                        \
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,                             \
                "%s(): payload inconsistency", __func__);                  \
        goto bad;                                                            \
    }                                                                        \
                                                                             \
    if (payload_s)                                                           \
    {                                                                        \
        n = libnet_pblock_append(l, p, payload, payload_s);                  \
        if (n == -1)                                                         \
        {                                                                    \
            goto bad;                                                        \
        }                                                                    \
    }                                                                        \
                                                                             \
    if (sum == 0)                                                            \
    {                                                                        \
        libnet_pblock_setflags(p, LIBNET_PBLOCK_DO_CHECKSUM);                \
    }                                                                        \
} while (0)

libnet_ptag_t
anubis_build_icmpv4_unreach(uint8_t type, uint8_t code, uint16_t sum, uint16_t mtu,
                            const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
    uint32_t n, h;
    libnet_pblock_t *p;
    anubis_icmp_t icmp_hdr;
    
    if (l == NULL)
    {
        return (-1);
    }
    n = LIBNET_ICMPV4_UNREACH_H + payload_s;        /* size of memory block */
    
    /*
     * FREDRAYNAL: as ICMP checksum includes what is embedded in
     * the payload, and what is after the ICMP header, we need to include
     * those 2 sizes.
     */
    h = LIBNET_ICMPV4_UNREACH_H + payload_s + l->total_size;
    
    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_ICMPV4_UNREACH_H);
    if (p == NULL)
    {
        return (-1);
    }
    
    memset(&icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr.icmp_type = type;          /* packet type */
    icmp_hdr.icmp_code = code;          /* packet code */
    icmp_hdr.icmp_cksum  = (sum ? htons(sum) : 0);  /* checksum */
    icmp_hdr.icmp_id   = 0;             /* must be 0 */
    icmp_hdr.icmp_seq  = 0;             /* must be 0 */
    
    /*fix here*/
    if(type == ICMP_UNREACH && code == ICMP_UNREACH_NEEDFRAG)
        icmp_hdr.icmp_nextmtu = (mtu ? htons(mtu) : 0); /*MTU of next hop*/
    
    LIBNET_BUILD_ICMP_ERR_FINISH(LIBNET_ICMPV4_UNREACH_H);
    
    return (ptag ? ptag : libnet_pblock_update(l, p, h,
                                               LIBNET_PBLOCK_ICMPV4_UNREACH_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}//end anubis_build_icmpv4_unreach

libnet_t *
anubis_libnet_init(int injection_type, const char *device, char *errbuf) {
    libnet_t *l = NULL;
	l = libnet_init(injection_type, device, errbuf);
	
    if(!l)
        return NULL;
    
    //try to fix libnet source code bug, it that a bug?
#if defined(BIOCGHDRCMPLT)
    uint spoof_eth_src = 1;
    if ((injection_type == LIBNET_LINK || injection_type == LIBNET_LINK_ADV) &&
        ioctl(l->fd, BIOCSHDRCMPLT, &spoof_eth_src) == -1) {
        snprintf(errbuf, LIBNET_ERRBUF_SIZE, "libnet_open_link(): BIOCSHDRCMPLT: %s", strerror(errno));
        goto bad;
    }
#endif
    return l;
    
bad:
    libnet_destroy(l);
    return NULL;
}//end anubis_libnet_init

static libnet_ptag_t
anubis_build_universal(const char *func, const uint8_t *data, uint32_t data_length,
                       const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag) {
    libnet_ptag_t tag = 0;
    
    //build payload
    if(payload && payload_s) {
        tag = libnet_build_data(payload,
                                payload_s,
                                l, LIBNET_PTAG_INITIALIZER);
        
        if(tag == -1) {
            anubis_err("%s", libnet_geterror(l));
        }//end if
    }//end if not build payload
    
    //build ssdp
    tag = libnet_build_data(data,
                            data_length,
                            l, ptag);
    if(tag == -1) {
        char *err = libnet_geterror(l);
        //error message
        if(!strncasecmp(err, "libnet_build_data(): ", strlen("libnet_build_data(): "))) {
            err += strlen("libnet_build_data(): ");
        }
        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE, "%s(): %s", func, err);
    }
    return tag;
}

libnet_ptag_t
anubis_build_rip(const uint8_t *data, uint32_t data_length,
                 const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag) {
    return anubis_build_universal("anubis_build_rip", data, data_length, payload, payload_s, l, ptag);
}//end anubis_build_rip

libnet_ptag_t
anubis_build_ssdp(const uint8_t *data, uint32_t data_length,
                  const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag) {
    return anubis_build_universal("anubis_build_ssdp", data, data_length, payload, payload_s, l, ptag);
}//end anubis_build_ssdp

libnet_ptag_t
anubis_build_http(const uint8_t *data, uint32_t data_length,
                  const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag) {
    return anubis_build_universal("anubis_build_http", data, data_length, payload, payload_s, l, ptag);
}//end anubis_build_http

libnet_ptag_t
anubis_build_dhcp_options(const uint8_t *data, uint32_t data_length,
                          const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag) {
    return anubis_build_universal("anubis_build_dhcp_options", data, data_length, payload, payload_s, l, ptag);
}//end anubis_build_dhcp_options

libnet_ptag_t
anubis_build_raw_data(const uint8_t *data, uint32_t data_length,
                      const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag) {
    return anubis_build_universal("anubis_build_raw_data", data, data_length, payload, payload_s, l, ptag);
}//end anubis_build_raw_data

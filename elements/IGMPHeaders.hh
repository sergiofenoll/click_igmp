#ifndef IGMP_H
#define IGMP_H

#include <clicknet/ip.h>

#define IGMP_TYPE_MEMBERSHIP_QUERY   0x11
#define IGMP_TYPE_MEMBERSHIP_REPORT  0x22

/* Mask usage: 
        igmp_S_QRV && <MASK> -> desired field
*/
#define   IGMP_RESV_MASK 0xf0
#define   IGMP_S_MASK    0x08
#define   IGMP_QRV_MASK  0x07

struct igmp_memb_query {

    uint8_t   igmp_type;
    uint8_t   igmp_max_resp_code;
    uint16_t  igmp_checksum;
    uint32_t  igmp_group_address;
    uint8_t   igmp_S_QRV; /* Format: xxxx x xxx - resv S QRV */
    uint8_t   igmp_QQIC;
    uint16_t  igmp_num_sources;
};


struct igmp_memb_report {
    uint8_t  igmp_type;
    uint8_t  resv1;
    uint16_t igmp_checksum;
    uint16_t resv2;
    uint16_t igmp_num_group_rec;
};

#define IGMP_MODE_IS_INCLUDE        1
#define IGMP_MODE_IS_EXCLUDE        2
#define IGMP_CHANGE_TO_INCLUDE_MODE 3
#define IGMP_CHANGE_TO_EXCLUDE_MODE 4

struct igmp_group_record {
    uint8_t  igmp_record_type;
    uint8_t  igmp_aux_data;
    uint16_t igmp_num_sources;
    uint32_t igmp_multicast_addr;
};


struct IP_options {
    uint8_t type;
    uint8_t length;
    uint16_t value;
};

#endif

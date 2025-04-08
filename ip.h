#ifndef PORTSCANNER_IP_H
#define PORTSCANNER_IP_H

#include <cstdint>

#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff


struct iphdr {
    uint8_t ihl:4,
            version:4;
    uint8_t	tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t	ttl;
    uint8_t	protocol;
    uint16_t checksum;
    uint32_t source_addr;
    uint32_t dest_addr;
};


#endif //PORTSCANNER_IP_H

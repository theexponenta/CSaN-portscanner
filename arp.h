#ifndef ARP_H
#define ARP_H

#include <cstdint>

#define ARP_ETH_HRD 1
#define ARP_IPV4_PRO 0x0800
#define ARP_ETH_HLN 6
#define ARP_IPV4_PLN 4
#define ARP_REQUEST_OP 1
#define ARP_RESPONSE_OP 2


struct etharp {
    uint16_t ar_hrd;
    uint16_t ar_pro;
    uint8_t ar_hln;
    uint8_t ar_pln;
    uint16_t ar_op;

    char ar_sha[ARP_ETH_HLN];
    uint32_t ar_spa;
    char ar_tha[ARP_ETH_HLN];
    uint32_t ar_tpa;
} __attribute__ ((__packed__));

#endif //ARP_H

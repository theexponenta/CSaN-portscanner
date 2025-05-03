#ifndef PORTSCANNER_TCP_H
#define PORTSCANNER_TCP_H

#include <cstdint>

struct tcphdr {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t res1: 4,
             data_off: 4,
             fin: 1,
             syn: 1,
             rst: 1,
             psh: 1,
             ack: 1,
             urg: 1,
             res2: 2;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
};


struct pseudo_tcphdr
{
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_length;

    tcphdr tcp;
};

#endif //PORTSCANNER_TCP_H

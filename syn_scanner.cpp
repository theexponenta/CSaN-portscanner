#include <vector>
#include <cstdint>
#include <cstdlib>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include "ip.h"
#include "tcp.h"
#include "random.h"
#include "utils.h"


#define DEFAULT_TTL 65
#define TCP_WINDOW_SIZE 14600

#define MIN_DYNAMIC_PORT 49152
#define MAX_DYNAMIC_PORT 65535


struct tcphash {
    uint32_t source_addr;
    uint16_t source_port;
    uint32_t dest_addr;
    uint16_t dest_port;
};


void synScan(std::vector<uint32_t> &hosts, std::vector<uint16_t> &ports) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    int one = 1;
    int res = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (const char*)&one, sizeof(one));

    char datagram[sizeof(iphdr) + sizeof(tcphdr)];
    memset(datagram, 0, sizeof(datagram));

    iphdr *iph = (iphdr*)datagram;
    tcphdr *tcph = (tcphdr*)(datagram + sizeof(iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(datagram));
    iph->id = rand();
    iph->frag_off = htons((iph->frag_off & IP_OFFMASK) | IP_DF);
    iph->ttl = DEFAULT_TTL;
    iph->protocol = IPPROTO_TCP;
    iph->source_addr = getLocalIp();

    tcph->syn = 1;
    tcph->data_off = sizeof(struct tcphdr) / 4;
    tcph->window = htons(TCP_WINDOW_SIZE);

    pseudo_tcphdr pseudoTcph {};
    pseudoTcph.source_address = iph->source_addr;

    tcphash tcpHash {};
    tcpHash.source_addr = iph->source_addr;
    char siphashKey[16];
    randBytes(siphashKey, sizeof(siphashKey));

    sockaddr_in destAddr {};
    destAddr.sin_family = AF_INET;

    for (uint32_t host : hosts) {
        iph->dest_addr = host;
        iph->checksum = 0;
        iph->checksum = checksum((uint16_t*)iph, sizeof(iphdr));

        pseudoTcph.dest_address = iph->dest_addr;
        destAddr.sin_addr.s_addr = iph->dest_addr;
        tcpHash.dest_addr = iph->dest_addr;

        for (uint16_t port : ports) {
            tcph->source_port = htons(randInt(MIN_DYNAMIC_PORT, MAX_DYNAMIC_PORT));
            tcph->dest_port = htons(port);
            tcph->window = htons(TCP_WINDOW_SIZE);
            tcph->checksum = 0;

            tcpHash.source_port = tcph->source_port;
            tcpHash.dest_port = tcph->dest_port;
            uint64_t hash;
            siphash(&tcpHash, sizeof(tcpHash), siphashKey, (uint8_t*)&hash, sizeof(hash));
            tcph->seq_num = htonl((uint32_t)hash);

            pseudoTcph.protocol = IPPROTO_TCP;
            pseudoTcph.tcp_length = htons(sizeof(tcphdr));
            memcpy(&pseudoTcph.tcp, tcph, sizeof(tcphdr));

            tcph->checksum = checksum((uint16_t*)&pseudoTcph, sizeof(pseudoTcph));

            destAddr.sin_port = htons(port);
            sendtoAll(sock, datagram, sizeof(datagram), 0, (sockaddr*)&destAddr, sizeof(destAddr));
        }
    }
}

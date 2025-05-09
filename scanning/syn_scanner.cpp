#include <vector>
#include <cstdint>
#include <cstdlib>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <cstring>
#include <map>
#include <thread>
#include <iostream>
#include "../ip.h"
#include "../tcp.h"
#include "../random.h"
#include "../utils.h"
#include "scanning.h"

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


void synScanReceive(ScanState &scanState) {
    char buffer[1600];
    iphdr *iph = (iphdr*)buffer;
    tcphdr *tcph = nullptr;
    tcphash tcpHash {};
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    while (!scanState.isEnd) {
        int bytesReceived = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (bytesReceived <= 0)
            continue;

        int length = htons(iph->tot_len);

        if (iph->protocol == IPPROTO_TCP) {
            tcph = (tcphdr*)(buffer + iph->ihl * 4);
            if (tcph->syn && tcph->ack) {
                tcpHash.source_addr = iph->dest_addr;
                tcpHash.source_port = tcph->dest_port;
                tcpHash.dest_addr = iph->source_addr;
                tcpHash.dest_port = tcph->source_port;

                uint64_t hash;
                siphash(&tcpHash, sizeof(tcpHash), scanState.params.seed, (uint8_t*)&hash, sizeof(hash));
                if (htonl(tcph->ack_num) - 1 == (uint32_t)hash) {
                    PortState portState = PortState::OPEN;
                    if (tcph->rst)
                        portState = PortState::CLOSED;

                    uint32_t ip = ntohl(iph->source_addr);
                    uint16_t port = ntohs(tcph->source_port);
                    scanState.result.addPortInfo(ip, port, portState);

                    char addrStr[32];
                    in_addr addr{};
                    addr.s_addr = iph->source_addr;
                    inet_ntop(AF_INET, &addr, addrStr, sizeof(addrStr));

                    std::cout << addrStr << ',' << port << '\n';
                }
            }
        }

        if (length > bytesReceived)
            idleRecvfromAll(sock, buffer, sizeof(buffer), length - bytesReceived, 0, nullptr, nullptr);
    }
}


void synScanTransmit(ScanState &scanState) {
    const ScanParams params = scanState.params;

    int sendSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    sockaddr_ll addr;
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = params.interface.index;

    bind(sendSock, (sockaddr*)&addr, sizeof(addr));

    char datagram[sizeof(ethhdr) + sizeof(iphdr) + sizeof(tcphdr)];
    memset(datagram, 0, sizeof(datagram));

    ethhdr *eth = (ethhdr*)datagram;
    iphdr *iph = (iphdr*)(datagram + sizeof(ethhdr));
    tcphdr *tcph = (tcphdr*)(datagram + sizeof(ethhdr) + sizeof(iphdr));

    eth->h_proto = htons(ETH_P_IP);
    memcpy(eth->h_source, params.interface.mac, sizeof(params.interface.mac));
    memcpy(eth->h_dest, params.interface.gatewayMac, sizeof(eth->h_dest));

    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr));
    iph->id = rand();
    iph->frag_off = htons((iph->frag_off & IP_OFFMASK) | IP_DF);
    iph->ttl = DEFAULT_TTL;
    iph->protocol = IPPROTO_TCP;
    iph->source_addr = htonl(params.interface.ip);

    tcph->syn = 1;
    tcph->data_off = sizeof(tcphdr) / 4;
    tcph->window = htons(TCP_WINDOW_SIZE);

    pseudo_tcphdr pseudoTcph {};
    pseudoTcph.source_address = iph->source_addr;
    pseudoTcph.protocol = IPPROTO_TCP;
    pseudoTcph.tcp_length = htons(sizeof(tcphdr));

    tcphash tcpHash {};
    tcpHash.source_addr = iph->source_addr;

    sockaddr_in destAddr {};
    destAddr.sin_family = AF_INET;

    for (uint32_t host : params.ips) {
        iph->dest_addr = host;
        iph->checksum = 0;
        iph->checksum = checksum((uint16_t*)iph, sizeof(iphdr));

        pseudoTcph.dest_address = iph->dest_addr;
        destAddr.sin_addr.s_addr = iph->dest_addr;
        tcpHash.dest_addr = iph->dest_addr;

        for (uint16_t port : params.ports) {
            tcph->source_port = htons(randInt(MIN_DYNAMIC_PORT, MAX_DYNAMIC_PORT));
            tcph->dest_port = htons(port);
            tcph->checksum = 0;

            tcpHash.source_port = tcph->source_port;
            tcpHash.dest_port = tcph->dest_port;
            uint64_t hash;
            siphash(&tcpHash, sizeof(tcpHash), params.seed, (uint8_t*)&hash, sizeof(hash));
            tcph->seq_num = htonl((uint32_t)hash);

            memcpy(&pseudoTcph.tcp, tcph, sizeof(tcphdr));

            tcph->checksum = checksum((uint16_t*)&pseudoTcph, sizeof(pseudoTcph));

            destAddr.sin_port = htons(port);
            sendAll(sendSock, datagram, sizeof(datagram), 0);
        }
    }
}


void synScan(ScanState &scanState) {
    std::thread receiveThread(synScanReceive, std::ref(scanState));
    std::thread transmitThread(synScanTransmit, std::ref(scanState));

    time_t start = time(nullptr);
    int messagesCount = scanState.params.ips.size() * scanState.params.ports.size();
    while (time(nullptr) - start <= scanState.params.wait && scanState.result.size() < messagesCount) {
        usleep(50000);
    }

    scanState.isEnd = true;

    transmitThread.join();
    receiveThread.join();
}

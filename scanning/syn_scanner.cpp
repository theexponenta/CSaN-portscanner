#include <vector>
#include <cstdint>
#include <cstdlib>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <map>
#include <thread>
#include "../ip.h"
#include "../tcp.h"
#include "../random.h"
#include "../utils.h"
#include "../arp.h"
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
    ethhdr *eth = (ethhdr*)buffer;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    bindSocketToInterface(sock, scanState.params.interface.index);

    while (!scanState.isEnd) {
        int bytesReceived = recv(sock, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0)
            continue;

        int length = 0;
        iphdr *iph = (iphdr*)(buffer + sizeof(ethhdr));

        if (eth->h_proto == htons(ETH_P_IP) && iph->protocol == IPPROTO_TCP) {
            length = htons(iph->tot_len);
            tcphdr *tcph = (tcphdr*)((char*)iph + iph->ihl * 4);
            tcphash tcpHash {};

            if ((tcph->syn && tcph->ack) || tcph->rst) {
                tcpHash.source_addr = iph->dest_addr;
                tcpHash.source_port = tcph->dest_port;
                tcpHash.dest_addr = iph->source_addr;
                tcpHash.dest_port = tcph->source_port;

                uint64_t hash;
                siphash(&tcpHash, sizeof(tcpHash), scanState.params.seed, (uint8_t*)&hash, sizeof(hash));
                if (htonl(tcph->ack_num) - 1 == (uint32_t)hash) {
                    PortState portState = PortState::OPEN;
                    if (tcph->rst) {
                        portState = PortState::CLOSED;
                    }

                    uint32_t ip = ntohl(iph->source_addr);
                    uint16_t port = ntohs(tcph->source_port);
                    scanState.result.addPortInfo(ip, port, portState);

                    char addrStr[32];
                    in_addr addr{};
                    addr.s_addr = iph->source_addr;
                    inet_ntop(AF_INET, &addr, addrStr, sizeof(addrStr));

                    if (!tcph->rst) {
                        char tempMac[6];
                        memcpy(tempMac, eth->h_source, ARP_ETH_HLN);
                        memcpy(eth->h_source, eth->h_dest, ARP_ETH_HLN);
                        memcpy(eth->h_dest, tempMac, ARP_ETH_HLN);

                        iph->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr));
                        iph->ttl = DEFAULT_TTL;
                        iph->frag_off = htons((iph->frag_off & IP_OFFMASK) | IP_DF);

                        uint32_t tempIp = iph->source_addr;
                        iph->source_addr = iph->dest_addr;
                        iph->dest_addr = tempIp;
                        iph->checksum = 0;

                        tcph->syn = 0;
                        tcph->ack = 0;
                        tcph->rst = 1;
                        tcph->seq_num = tcph->ack_num;
                        tcph->ack_num = 0;
                        tcph->data_off = sizeof(tcphdr) / 4;
                        tcph->window = 0;

                        uint16_t tempPort = tcph->source_port;
                        tcph->source_port = tcph->dest_port;
                        tcph->dest_port = tempPort;
                        tcph->checksum = 0;

                        pseudo_tcphdr pseudoTcph {};
                        pseudoTcph.source_address = iph->source_addr;
                        pseudoTcph.dest_address = iph->dest_addr;
                        pseudoTcph.protocol = IPPROTO_TCP;
                        pseudoTcph.tcp_length = htons(sizeof(tcphdr));
                        memcpy(&pseudoTcph.tcp, tcph, sizeof(tcphdr));

                        iph->checksum = checksum((uint16_t*)iph, sizeof(iphdr));
                        tcph->checksum = checksum((uint16_t*)&pseudoTcph, sizeof(pseudoTcph));

                        sendAll(sock, buffer, sizeof(ethhdr) + sizeof(iphdr) + sizeof(tcphdr), 0);
                    }

                    for (std::ofstream *stream : scanState.params.ofstreams) {
                        *stream << addrStr << ',' << port << ',' << getPortStateName(portState) << std::endl;
                    }
                }
            }
        } else if (eth->h_proto == htons(ETH_P_ARP)) {
            etharp *arph = (etharp*)(buffer + sizeof(ethhdr));
            if (arph->ar_op == htons(ARP_REQUEST_OP) && arph->ar_tpa == htonl(scanState.params.interface.spoofedIp)) {
                memcpy(eth->h_source, arph->ar_tha, sizeof(eth->h_source));
                memcpy(eth->h_dest, arph->ar_sha, sizeof(eth->h_dest));

                etharp *response = arph;
                uint32_t temp = response->ar_tpa;
                response->ar_tpa = response->ar_spa;
                response->ar_spa = temp;
                response->ar_op = htons(ARP_RESPONSE_OP);
                memcpy(response->ar_sha, scanState.params.interface.mac, ARP_ETH_HLN);

                sendAll(sock, buffer, sizeof(etharp) + sizeof(ethhdr), 0);
            }
        }

        if (length > bytesReceived)
            idleRecvAll(sock, buffer, sizeof(buffer), length - bytesReceived, 0);
    }
}


void synScanTransmit(ScanState &scanState) {
    const ScanParams params = scanState.params;

    int sendSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    bindSocketToInterface(sendSock, params.interface.index);

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
    iph->source_addr = htonl(params.interface.spoofedIp);

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
        iph->dest_addr = htonl(host);
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

    transmitThread.join();

    time_t start = time(nullptr);
    int messagesCount = scanState.params.ips.size() * scanState.params.ports.size();
    while (time(nullptr) - start <= scanState.params.wait && scanState.result.size() < messagesCount) {
        usleep(50000);
    }

    scanState.isEnd = true;

    receiveThread.join();
}

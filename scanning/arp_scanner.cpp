#include "arp_scanner.h"
#include <cstring>
#include <thread>
#include <fstream>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "scanning.h"
#include "../utils.h"
#include "../arp.h"


#define ARPSCAN_RECV_BUFFER_SIZE 200
#define MAC_STR_LEN 17


void arpScanTransmit(ScanState &scanState) {
    char buffer[sizeof(ethhdr) + sizeof(etharp)];

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    bindSocketToInterface(sock, scanState.params.interface.index);

    ethhdr *eth = (ethhdr*)buffer;
    eth->h_proto = htons(ETH_P_ARP);
    std::memcpy(eth->h_source, scanState.params.interface.mac, sizeof(eth->h_source));
    std::memset(eth->h_dest, 0xff, sizeof(eth->h_dest));

    etharp *arpReq = (etharp*)(buffer + sizeof(ethhdr));

    arpReq->ar_hrd = htons(ARP_ETH_HRD);
    arpReq->ar_pro = htons(ARP_IPV4_PRO);
    arpReq->ar_hln = ARP_ETH_HLN;
    arpReq->ar_pln = ARP_IPV4_PLN;
    arpReq->ar_op = htons(ARP_REQUEST_OP);
    memcpy(arpReq->ar_sha, scanState.params.interface.mac, ARP_ETH_HLN);
    memset(arpReq->ar_tha, 0, ARP_ETH_HLN);
    arpReq->ar_spa = htonl(scanState.params.interface.ip);

    for (uint32_t host : scanState.params.ips) {
        arpReq->ar_tpa = htonl(host);
        sendAll(sock, buffer, sizeof(buffer), 0);
    }

    close(sock);
}


void arpScanReceive(ScanState &scanState) {
    char datagram[ARPSCAN_RECV_BUFFER_SIZE];
    char macAddrStr[MAC_STR_LEN + 1];
    char ipAddrStr[32];
    in_addr addr{};

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    bindSocketToInterface(sock, scanState.params.interface.index);

    while (!scanState.isEnd) {
        int bytesReceived = recv(sock, datagram, sizeof(datagram), 0);
        if (bytesReceived <= 0)
            continue;

        etharp *arpResponse = (etharp*)(datagram + sizeof(ethhdr));

        if (arpResponse->ar_op != htons(ARP_RESPONSE_OP))
            continue;

        if (arpResponse->ar_tpa != htonl(scanState.params.interface.ip))
            continue;

        addr.s_addr = arpResponse->ar_spa;
        inet_ntop(AF_INET, &addr, ipAddrStr, sizeof(ipAddrStr));

        macToStr(arpResponse->ar_sha, macAddrStr);

        for (std::ofstream *stream : scanState.params.ofstreams) {
            *stream << ipAddrStr << ',' << macAddrStr << std::endl;
        }
    }
}


void arpScan(ScanState &scanState) {
    std::thread receiveThread(arpScanReceive, std::ref(scanState));
    std::thread transmitThread(arpScanTransmit, std::ref(scanState));

    transmitThread.join();

    usleep(scanState.params.wait * 1e6);

    scanState.isEnd = true;

    receiveThread.join();
}

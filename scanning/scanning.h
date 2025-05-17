#ifndef SCANNING_H
#define SCANNING_H

#include <cstdint>
#include <vector>
#include <map>
#include <net/if.h>
#include <string>


struct NetworkInterface {
    int index;
    char name[IFNAMSIZ];
    unsigned char mac[6];
    unsigned char gatewayMac[6];
    uint32_t ip;
    uint32_t spoofedIp;
    uint32_t gatewayIp;
};


struct ScanParams {
    std::vector<uint32_t> ips;
    std::vector<uint16_t> ports;
    NetworkInterface interface;
    unsigned int wait;
    char seed[16];
};


enum PortState {
    OPEN,
    CLOSED,
    FILTERED
};

std::string getPortStateName(PortState state);

struct PortInfo {
    uint16_t port;
    PortState state;
};


struct HostInfo {
    uint32_t ip;
    std::vector<PortInfo> portsInfo;
};


class ScanResult {
    std::map<uint32_t, int> hostsInfoIndices_;
    std::vector<HostInfo> hostsInfo_;
    int size_ = 0;

public:

    void addPortInfo(uint32_t hostIp, uint16_t port, PortState portState);
    int size() const;
    const std::vector<HostInfo>& hostsInfo() const &;
};


struct ScanState {
    const ScanParams &params;
    ScanResult result;
    volatile bool isEnd = false;

    ScanState(const ScanParams &params) : params(params) {}
};

#endif //SCANNING_H

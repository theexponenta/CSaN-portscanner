#ifndef SCANNING_H
#define SCANNING_H

#include <cstdint>
#include <vector>
#include <map>


struct ScanParams {
    std::vector<uint32_t> ips;
    std::vector<uint16_t> ports;
    unsigned int wait;
    char seed[16];
};


enum PortState {
    OPEN,
    CLOSED,
    FILTERED
};


struct PortInfo {
    uint16_t port;
    PortState state;
};


struct HostInfo {
    uint32_t ip;
    std::vector<PortInfo> portsInfo;
};


class ScanResult {
    std::map<uint32_t, HostInfo> hosts;

public:

    void addPortInfo(uint32_t hostIp, uint16_t port, PortState portState);
};

#endif //SCANNING_H

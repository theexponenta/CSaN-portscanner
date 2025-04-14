#include "scanning.h"

void ScanResult::addPortInfo(uint32_t hostIp, uint16_t port, PortState portState) {
    if (!this->hosts.contains(hostIp)) {
        HostInfo hostInfo;
        hostInfo.ip = hostIp;
        this->hosts[hostIp] = hostInfo;
    }

    this->hosts[hostIp].portsInfo.push_back(PortInfo {port, portState});
}

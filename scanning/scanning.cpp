#include "scanning.h"

void ScanResult::addPortInfo(uint32_t hostIp, uint16_t port, PortState portState) {
    int index = -1;
    if (!this->hostsInfoIndices_.contains(hostIp)) {
        HostInfo hostInfo;
        hostInfo.ip = hostIp;

        index = this->hostsInfo_.size();
        this->hostsInfoIndices_[hostIp] = index;
        this->hostsInfo_.push_back(std::move(hostInfo));
    }

    if (index == -1)
        index = this->hostsInfoIndices_[hostIp];

    this->hostsInfo_[index].portsInfo.push_back(PortInfo {port, portState});
    this->size_++;
}


int ScanResult::size() const {
    return this->size_;
}


const std::vector<HostInfo>& ScanResult::hostsInfo() const & {
    return this->hostsInfo_;
}


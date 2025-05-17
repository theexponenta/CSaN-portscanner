#include <iostream>
#include <sys/socket.h>
#include <ctime>
#include <fstream>
#include <arpa/inet.h>
#include "scanning/scanning.h"
#include "scanning/syn_scanner.h"
#include "random.h"
#include "cli.h"
#include "utils.h"


int getScanParams(int argc, char **argv, ScanParams &params) {
    if (getCliScanParams(params, argc, argv))
        return -1;

    params.wait = 10;
    randBytes(params.seed, sizeof(ScanParams::seed));
    randBytes(&params.interface.spoofedIp, sizeof(params.interface.spoofedIp));

    return 0;
}


int main(int argc, char** argv) {
    srand(time(nullptr));

    ScanParams scanParams {};
    if (getScanParams(argc, argv, scanParams))
        return -1;

    ScanState scanState {scanParams};
    synScan(scanState);

    for (auto &host : scanState.result.hostsInfo()) {
        char addrStr[32];
        in_addr addr{};
        addr.s_addr = htonl(host.ip);
        inet_ntop(AF_INET, &addr, addrStr, sizeof(addrStr));

        std::cout << addrStr << "\n";

        for (const PortInfo &portInfo : host.portsInfo) {
            std::cout << portInfo.port << " ";

            if (portInfo.state == PortState::OPEN)
                std::cout << "OPEN";
            else
                std::cout << "CLOSED";

            std::cout << '\n';
        }

        std::cout << '\n';
    }

    return 0;
}

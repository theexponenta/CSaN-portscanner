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


int main(int argc, char** argv) {
    srand(time(nullptr));

    ScanParams scanParams {};
    scanParams.wait = 10;
    randBytes(scanParams.seed, sizeof(ScanParams::seed));
    if (getScanParams(scanParams, argc, argv))
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

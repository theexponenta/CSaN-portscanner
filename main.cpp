#include <iostream>
#include <sys/socket.h>
#include <ctime>
#include <fstream>
#include <arpa/inet.h>
#include "scanning/scanning.h"
#include "scanning/syn_scanner.h"
#include "random.h"
#include "cli.h"
#include "scanning/arp_scanner.h"


int getScanParams(int argc, char **argv, ScanParams &params) {
    params.scanType = ScanType::SYN;
    params.interface.spoofedIp = 0;

    std::ofstream *stdOut = new std::ofstream();
    *stdOut->basic_ios<char>::rdbuf(std::cout.rdbuf());
    params.ofstreams.push_back(stdOut);

    if (getCliScanParams(params, argc, argv))
        return -1;

    params.wait = 10;
    randBytes(params.seed, sizeof(ScanParams::seed));
    if (params.interface.spoofedIp == 0)
        params.interface.spoofedIp = params.interface.ip;

    return 0;
}


int main(int argc, char** argv) {
    srand(time(nullptr));

    ScanParams scanParams {};
    if (getScanParams(argc, argv, scanParams))
        return -1;

    ScanState scanState {scanParams};

    if (scanParams.scanType == ScanType::SYN)
        synScan(scanState);
    else if (scanParams.scanType == ScanType::ARP)
        arpScan(scanState);

    for (std::ofstream* stream : scanParams.ofstreams) {
        stream->close();
        delete stream;
    }

    return 0;
}

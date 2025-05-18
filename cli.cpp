#include <iostream>
#include <fstream>
#include "scanning/scanning.h"
#include "cli.h"
#include "utils.h"
#include <string>
#include <arpa/inet.h>


using param_setter = int (*)(ScanParams &params, char* value);


struct ScanCLIParam {
    std::string name;
    param_setter setter;
    char flags;
};


int setPorts(ScanParams &params, char *value) {
    char *start = value;

    std::string token;
    while (*value) {
        if (*value == ',') {
            token.clear();
            token.append(start, value);
            params.ports.push_back(std::atoi(token.c_str()));
            start = value + 1;
        }
        ++value;
    }

    if (*start != '\0') {
        token.clear();
        token.append(start);
        params.ports.push_back(std::atoi(token.c_str()));
    }

    return 0;
}


int setNetworkInterface(ScanParams &params, char *value) {
    if (getNetworkInterfaceByName(value, params.interface)) {
        std::cout << "Can't get network interface \"" << value << "\"\n";
        return -1;
    }

    return 0;
}


int setSourceIp(ScanParams &params, char *value) {
    in_addr addr;
    if (inet_aton(value, &addr) == 0) {
        std::cout << "Invalid source address: " << value;
        return -1;
    }

    params.interface.spoofedIp = ntohl(addr.s_addr);

    return 0;
}


int setOutput(ScanParams &params, char *value) {
    std::ofstream *output = new std::ofstream(value);
    if (output->fail()) {
        std::cout << "Can't open file " << value;
        delete output;
        return -1;
    }

    params.ofstreams.push_back(output);

    return 0;
}


const ScanCLIParam SCAN_CLI_PARAMS[] = {
    {"ports", setPorts, 0},
    {"interface", setNetworkInterface, 0},
    {"source-ip", setSourceIp, 0},
    {"output", setOutput, 0}
};


int setParam(ScanParams &params, std::string &name, char *value) {
    int paramsCount = sizeof(SCAN_CLI_PARAMS) / sizeof(ScanCLIParam);
    for (int i = 0; i < paramsCount; i++) {
        if (SCAN_CLI_PARAMS[i].name == name) {
            return SCAN_CLI_PARAMS[i].setter(params, value);
        }
    }

    return -1;
}


char *firstNonAlphanumeric(char* str) {
    char c = str[0];
    while (c && (c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
        str++;
        c = *str;
    }

    return str;
}


int getCliScanParams(ScanParams &params, int argc, char** argv) {
    params.interface.ip = 0;

    std::string paramName;

    for (int i = 1; i < argc; i++) {
        paramName.clear();
        bool isOption = false;

        if (argv[i][0] == '-' && argv[i][1] == '-') {
            char *paramNameStart = argv[i] + 2;
            paramName.append(paramNameStart, firstNonAlphanumeric(paramNameStart));
            isOption = true;
        }

        if (isOption) {
            if (i == argc - 1)
                break;

            if (setParam(params, paramName, argv[i + 1]))
                return -1;

            i++;
        } else {
            uint32_t addr = inet_addr(argv[i]);
            if (addr == INADDR_NONE)
                continue;

            params.ips.push_back(addr);
        }
    }

    if (params.interface.ip == 0) {
        if (getDefaultNetworkInterface(params.interface)) {
            std::cout << "Can't find suitable network interface. Try to specify it via --interface option.\n";
            return -1;
        }
    }

    return 0;
}

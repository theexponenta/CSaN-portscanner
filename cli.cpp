#include "scanning/scanning.h"
#include "cli.h"
#include <string>
#include <arpa/inet.h>


using param_setter = void (*)(ScanParams &params, char* value);


struct ScanCLIParam {
    std::string name;
    param_setter setter;
    char flags;
};


void setPorts(ScanParams &params, char *value) {
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
}


const ScanCLIParam SCAN_CLI_PARAMS[] = {
    {"ports", setPorts, 0}
};


void setParam(ScanParams &params, std::string &name, char *value) {
    int paramsCount = sizeof(SCAN_CLI_PARAMS) / sizeof(ScanCLIParam);
    for (int i = 0; i < paramsCount; i++) {
        if (SCAN_CLI_PARAMS[i].name == name) {
            SCAN_CLI_PARAMS[i].setter(params, value);
        }
    }
}


char *firstNonAlphanumeric(char* str) {
    char c = str[0];
    while (c && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) {
        str++;
        c = *str;
    }

    return str;
}


void getScanParams(ScanParams &params, int argc, char** argv) {
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

            setParam(params, paramName, argv[i + 1]);
            i++;
        } else {
            uint32_t addr = inet_addr(argv[i]);
            if (addr == INADDR_NONE)
                continue;

            params.ips.push_back(addr);
        }
    }
}

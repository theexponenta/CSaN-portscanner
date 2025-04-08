#ifndef PORTSCANNER_SYN_SCANNER_H
#define PORTSCANNER_SYN_SCANNER_H

#include <vector>
#include <cstdint>

void synScan(std::vector<uint32_t> &hosts, std::vector<uint16_t> &ports);

#endif

#ifndef PORTSCANNER_SYN_SCANNER_H
#define PORTSCANNER_SYN_SCANNER_H

#include <vector>
#include <cstdint>
#include <map>
#include "scanning.h"

void synScanTransmit(ScanParams *scanParams);
void synScanReceive(ScanParams *scanParams, ScanResult *result);

#endif

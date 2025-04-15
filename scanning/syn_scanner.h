#ifndef PORTSCANNER_SYN_SCANNER_H
#define PORTSCANNER_SYN_SCANNER_H

#include <vector>
#include <cstdint>
#include <map>
#include "scanning.h"

void synScanTransmit(ScanState &scanState);
void synScanReceive(ScanState &scanState);

#endif

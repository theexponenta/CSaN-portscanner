#ifndef PORTSCANNER_UTILS_H
#define PORTSCANNER_UTILS_H

#include <cstdint>
#include "scanning/scanning.h"

uint16_t checksum(uint16_t *buffer, int bytesCount);
int siphash(const void *in, const size_t inlen, const void *k, uint8_t *out, const size_t outlen);
uint32_t getLocalIp();
int sendAll(int s, const char *buf, int len, int flags);
int sendtoAll(int s, const char *buf, int len, int flags, const sockaddr *to, int tolen);
int idleRecvAll(int s, void *buf, int bufLen, int readLen, int flags);
int idleRecvfromAll(int s, void *buf, int bufLen, int readLen, int flags, sockaddr *from , socklen_t *fromlen);
int getDefaultNetworkInterface(NetworkInterface &interface);
int getNetworkInterfaceByName(char *name, NetworkInterface &interface);
int getDefaultGateway(int ifindex, uint32_t *ipv4);

#endif //PORTSCANNER_UTILS_H

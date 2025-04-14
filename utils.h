#ifndef PORTSCANNER_UTILS_H
#define PORTSCANNER_UTILS_H

#include <cstdint>

uint16_t checksum(uint16_t *buffer, int bytesCount);
int siphash(const void *in, const size_t inlen, const void *k, uint8_t *out, const size_t outlen);
uint32_t getLocalIp();
int sendtoAll(int s, const char *buf, int len, int flags, const sockaddr *to, int tolen);
int idleRecvfromAll(int s, void *buf, int len, int flags, sockaddr *from , socklen_t *fromlen);

#endif //PORTSCANNER_UTILS_H

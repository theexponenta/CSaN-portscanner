#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "utils.h"


#ifndef cROUNDS
#define cROUNDS 2
#endif
#ifndef dROUNDS
#define dROUNDS 4
#endif


#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))

#define U32TO8_LE(p, v)                                                        \
    (p)[0] = (uint8_t)((v));                                                   \
    (p)[1] = (uint8_t)((v) >> 8);                                              \
    (p)[2] = (uint8_t)((v) >> 16);                                             \
    (p)[3] = (uint8_t)((v) >> 24);

#define U64TO8_LE(p, v)                                                        \
    U32TO8_LE((p), (uint32_t)((v)));                                           \
    U32TO8_LE((p) + 4, (uint32_t)((v) >> 32));

#define U8TO64_LE(p)                                                           \
    (((uint64_t)((p)[0])) | ((uint64_t)((p)[1]) << 8) |                        \
     ((uint64_t)((p)[2]) << 16) | ((uint64_t)((p)[3]) << 24) |                 \
     ((uint64_t)((p)[4]) << 32) | ((uint64_t)((p)[5]) << 40) |                 \
     ((uint64_t)((p)[6]) << 48) | ((uint64_t)((p)[7]) << 56))

#define SIPROUND                                                               \
    do {                                                                       \
        v0 += v1;                                                              \
        v1 = ROTL(v1, 13);                                                     \
        v1 ^= v0;                                                              \
        v0 = ROTL(v0, 32);                                                     \
        v2 += v3;                                                              \
        v3 = ROTL(v3, 16);                                                     \
        v3 ^= v2;                                                              \
        v0 += v3;                                                              \
        v3 = ROTL(v3, 21);                                                     \
        v3 ^= v0;                                                              \
        v2 += v1;                                                              \
        v1 = ROTL(v1, 17);                                                     \
        v1 ^= v2;                                                              \
        v2 = ROTL(v2, 32);                                                     \
    } while (0)


#define SOME_SERVER "1.1.1.1"
#define SOME_PORT 53


uint16_t checksum(uint16_t *buffer, int bytesCount) {
    uint32_t sum = 0;

    while (bytesCount > 1)  {
        sum += *(buffer++);
        bytesCount -= 2;
    }

    if (bytesCount > 0)
        sum +=  *buffer;

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}


int siphash(const void *in, const size_t inlen, const void *k, uint8_t *out,
            const size_t outlen) {

    const unsigned char *ni = (const unsigned char *)in;
    const unsigned char *kk = (const unsigned char *)k;

    uint64_t v0 = UINT64_C(0x736f6d6570736575);
    uint64_t v1 = UINT64_C(0x646f72616e646f6d);
    uint64_t v2 = UINT64_C(0x6c7967656e657261);
    uint64_t v3 = UINT64_C(0x7465646279746573);
    uint64_t k0 = U8TO64_LE(kk);
    uint64_t k1 = U8TO64_LE(kk + 8);
    uint64_t m;
    int i;
    const unsigned char *end = ni + inlen - (inlen % sizeof(uint64_t));
    const int left = inlen & 7;
    uint64_t b = ((uint64_t)inlen) << 56;
    v3 ^= k1;
    v2 ^= k0;
    v1 ^= k1;
    v0 ^= k0;

    if (outlen == 16)
        v1 ^= 0xee;

    for (; ni != end; ni += 8) {
        m = U8TO64_LE(ni);
        v3 ^= m;

        for (i = 0; i < cROUNDS; ++i)
            SIPROUND;

        v0 ^= m;
    }

    switch (left) {
        case 7:
            b |= ((uint64_t)ni[6]) << 48;
            /* FALLTHRU */
        case 6:
            b |= ((uint64_t)ni[5]) << 40;
            /* FALLTHRU */
        case 5:
            b |= ((uint64_t)ni[4]) << 32;
            /* FALLTHRU */
        case 4:
            b |= ((uint64_t)ni[3]) << 24;
            /* FALLTHRU */
        case 3:
            b |= ((uint64_t)ni[2]) << 16;
            /* FALLTHRU */
        case 2:
            b |= ((uint64_t)ni[1]) << 8;
            /* FALLTHRU */
        case 1:
            b |= ((uint64_t)ni[0]);
            break;
        case 0:
            break;
    }

    v3 ^= b;

    for (i = 0; i < cROUNDS; ++i)
        SIPROUND;

    v0 ^= b;

    if (outlen == 16)
        v2 ^= 0xee;
    else
        v2 ^= 0xff;

    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(out, b);

    if (outlen == 8)
        return 0;

    v1 ^= 0xdd;

    for (i = 0; i < dROUNDS; ++i)
        SIPROUND;

    b = v0 ^ v1 ^ v2 ^ v3;
    U64TO8_LE(out + 8, b);

    return 0;
}


uint32_t getLocalIp() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return 0;

    sockaddr_in serverAddr {};
    serverAddr.sin_addr.s_addr = inet_addr(SOME_SERVER);
    serverAddr.sin_port = htons(SOME_PORT);
    serverAddr.sin_family = AF_INET;

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
        return 0;

    sockaddr_in myAddr {};
    socklen_t myAddrLen = sizeof(myAddr);
    if (getsockname(sock, (sockaddr*)&myAddr, &myAddrLen) < 0)
        return 0;

    close(sock);
    return myAddr.sin_addr.s_addr;
}


int sendtoAll(int s, const char *buf, int len, int flags, const sockaddr *to, int tolen) {
    int bytesSent = 0;
    while (len > 0) {
        bytesSent = sendto(s, buf, len, flags, to, tolen);
        if (bytesSent <= 0)
            break;

        len -= bytesSent;
        buf += bytesSent;
    }

    return bytesSent;
}

#include <cstring>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/rtnetlink.h>
#include <netinet/if_ether.h>
#include <cerrno>
#include <ctime>
#include "utils.h"
#include "arp.h"
#include "scanning/scanning.h"

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

#define MAC_LENGTH 6

#define ARP_RESPONSE_BUF_SIZE 200
#define ARP_RESPONSE_TIMEOUT 2


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


int sendAll(int s, const char *buf, int len, int flags) {
    int bytesSent = 0;
    while (len > 0) {
        bytesSent = send(s, buf, len, flags);
        if (bytesSent <= 0)
            break;

        len -= bytesSent;
        buf += bytesSent;
    }

    return bytesSent;
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


int idleRecvfromAll(int s, void *buf, int bufLen, int readLen, int flags, sockaddr *from , socklen_t *fromlen) {
    while (readLen > 0) {
        int bytesReceived = recvfrom(s, buf, bufLen, flags, from, fromlen);
        if (bytesReceived <= 0)
            break;

        readLen -= bytesReceived;
    }

    return readLen;
}


int idleRecvAll(int s, void *buf, int bufLen, int readLen, int flags) {
    while (readLen > 0) {
        int bytesReceived = recv(s, buf, bufLen, flags);
        if (bytesReceived <= 0)
            break;

        readLen -= bytesReceived;
    }

    return readLen;
}


int arpRequest(uint32_t srcIp, uint32_t targetIp, int ifindex, const char *srcMac, char *resultMac) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0)
        return -1;

    timeval timeout;
    timeout.tv_sec = ARP_RESPONSE_TIMEOUT;
    timeout.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
        close(sock);
        return -1;
    }

    sockaddr_ll addr;
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifindex;

    if (bind(sock, (sockaddr*)&addr, sizeof(addr))) {
        close(sock);
        return -1;
    }

    char datagram[sizeof(ethhdr) + sizeof(ether_arp)];
    memset(datagram, 0, sizeof(datagram));

    ethhdr *eth = (ethhdr*)datagram;
    etharp *arpReq = (etharp*)(datagram + sizeof(ethhdr));

    eth->h_proto = htons(ETH_P_ARP);
    memcpy(eth->h_source, srcMac, MAC_LENGTH);
    memset(eth->h_dest, 0xff, MAC_LENGTH);

    arpReq->ar_hrd = htons(ARP_ETH_HRD);
    arpReq->ar_pro = htons(ARP_IPV4_PRO);
    arpReq->ar_hln = ARP_ETH_HLN;
    arpReq->ar_pln = ARP_IPV4_PLN;
    arpReq->ar_op = htons(ARP_REQUEST_OP);
    memcpy(arpReq->ar_sha, srcMac, MAC_LENGTH);
    arpReq->ar_spa = htonl(srcIp);
    arpReq->ar_tpa = htonl(targetIp);

    if (sendAll(sock, datagram, sizeof(datagram), 0) <= 0) {
        close(sock);
        return -1;
    }

    char response[ARP_RESPONSE_BUF_SIZE];
    etharp *arpResponse;

    bool responseReceived = false;
    time_t start = time(nullptr);
    do {
        int bytesReceived = recv(sock, response, sizeof(response), 0);
        if (bytesReceived <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
            continue;

        arpResponse = (etharp*)(response + sizeof(ethhdr));

        if (arpResponse->ar_op != htons(ARP_RESPONSE_OP))
            continue;

        if (arpResponse->ar_spa != htonl(targetIp))
            continue;

        if (arpResponse->ar_tpa != htonl(srcIp))
            continue;

        if (memcmp(arpResponse->ar_tha, srcMac, MAC_LENGTH) == 0)
            responseReceived = true;

    } while (!responseReceived && time(nullptr) - start < ARP_RESPONSE_TIMEOUT);

    close(sock);

    if (!responseReceived)
        return -1;

    memcpy(resultMac, arpResponse->ar_sha, MAC_LENGTH);
    return 0;
}


struct RouteInfo {
    in_addr dstAddr;
    in_addr srcAddr;
    in_addr gateway;
    int ifindex;
};


static int readNetlink(int fd, char *bufPtr, size_t sizeof_buffer, int seqNum, int pId) {
    nlmsghdr *nlHdr;
    int readLen = 0, msgLen = 0;

    do {
        /* Receive response from the kernel */
        if ((readLen = recv(fd, bufPtr, sizeof_buffer - msgLen, 0)) < 0) {
            return -1;
        }

        nlHdr = (nlmsghdr *) bufPtr;

        if ((NLMSG_OK(nlHdr, readLen) == 0)|| (nlHdr->nlmsg_type == NLMSG_ERROR)) {
            return -1;
        }

        if (nlHdr->nlmsg_type == NLMSG_DONE) {
            break;
        }

        bufPtr += readLen;
        msgLen += readLen;

        if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0) {
            break;
        }

    } while ((nlHdr->nlmsg_seq != seqNum) || (nlHdr->nlmsg_pid != pId));

    return msgLen;
}


static int parseRoutes(nlmsghdr *nlHdr, RouteInfo *rtInfo) {
    rtmsg *rtMsg;
    rtattr *rtAttr;
    int rtLen = 0;

    rtMsg = (rtmsg *) NLMSG_DATA(nlHdr);

    /* This must be an IPv4 (AF_INET) route */
    if (rtMsg->rtm_family != AF_INET)
        return 1;

    /* This must be in main routing table */
    if (rtMsg->rtm_table != RT_TABLE_MAIN)
        return 1;

    /* Attributes field*/
    rtAttr = (rtattr *)RTM_RTA(rtMsg);
    rtLen = RTM_PAYLOAD(nlHdr);
    for (; RTA_OK(rtAttr, rtLen); rtAttr = RTA_NEXT(rtAttr, rtLen)) {
        switch (rtAttr->rta_type) {
        case RTA_OIF:
            rtInfo->ifindex = *(int *)RTA_DATA(rtAttr);
            break;
        case RTA_GATEWAY:
            rtInfo->gateway.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_PREFSRC:
            rtInfo->srcAddr.s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        case RTA_DST:
            rtInfo->dstAddr .s_addr = *(u_int *)RTA_DATA(rtAttr);
            break;
        }
    }

    return 0;
}


int getDefaultGateway(int ifindex, uint32_t *ipv4) {
    int fd;
    nlmsghdr *nlMsg;
    char msgBuf[16384];
    int len;
    int msgSeq = 0;

    *ipv4 = 0;

    fd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (fd < 0)
        return errno;

    memset(msgBuf, 0, sizeof(msgBuf));
    nlMsg = (nlmsghdr *)msgBuf;

    nlMsg->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    nlMsg->nlmsg_type = RTM_GETROUTE;
    nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nlMsg->nlmsg_seq = msgSeq++;
    nlMsg->nlmsg_pid = getpid();

    if (send(fd, nlMsg, nlMsg->nlmsg_len, 0) < 0)
        return errno;

    len = readNetlink(fd, msgBuf, sizeof(msgBuf), msgSeq, getpid());
    if (len <= 0)
        return errno;

    for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
        RouteInfo rtInfo[1];
        int err;

        memset(rtInfo, 0, sizeof(RouteInfo));

        err = parseRoutes(nlMsg, rtInfo);
        if (err != 0)
            continue;

        /* make sure we match the desired network interface */
        if (ifindex && ifindex != rtInfo->ifindex)
            continue;

        /* make sure destination = 0.0.0.0 for "default route" */
        if (rtInfo->dstAddr.s_addr != 0)
            continue;

        /* found the gateway! */
        *ipv4 = ntohl(rtInfo->gateway.s_addr);
    }

    close(fd);

    return 0;
}


bool getAutoNetworkInterface(NetworkInterface &interface) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0)
        return false;

    bool result = false;
    struct if_nameindex *interfaces = if_nameindex();
    struct if_nameindex *curInterface = interfaces;
    ifreq ifr {};

    for (; curInterface->if_index != 0; curInterface++) {
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_addr.sa_family = AF_INET;
        strcpy(ifr.ifr_name, curInterface->if_name);

        if (ioctl(sock, SIOCGIFFLAGS, &ifr))
            continue;

        int flags = ifr.ifr_flags;
        if ((flags & IFF_LOOPBACK) || !(flags & IFF_UP) || !(flags & IFF_RUNNING))
            continue;

        if (ioctl(sock, SIOCGIFADDR, &ifr))
            continue;

        interface.ip = ntohl(((sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);

        if (ioctl(sock, SIOCGIFHWADDR, &ifr))
            continue;

        interface.index = curInterface->if_index;
        memcpy(interface.mac, ifr.ifr_hwaddr.sa_data, sizeof(interface.mac));
        strcpy(interface.name, curInterface->if_name);
        result = true;
    }

    close(sock);
    if_freenameindex(interfaces);

    if (!result)
        return false;

    uint32_t defaultGatewayIp = 0;
    if (getDefaultGateway(interface.index, &defaultGatewayIp))
        return false;

    if (defaultGatewayIp == 0) {
        memset(interface.gatewayMac, 0, sizeof(interface.mac));
        interface.gatewayIp = interface.ip;
    }
    else {
        interface.gatewayIp = defaultGatewayIp;
        if (arpRequest(interface.ip, defaultGatewayIp, interface.index, (const char*)interface.mac, (char*)interface.gatewayMac))
            return false;
    }

    return true;
}

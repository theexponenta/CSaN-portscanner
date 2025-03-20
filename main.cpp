#include <iostream>
#include <winsock2.h>

#define WS_VERSION 0x0202


int main() {
    WSAData wsaData;
    WSAStartup(WS_VERSION, &wsaData);

    WSACleanup();
    return 0;
}

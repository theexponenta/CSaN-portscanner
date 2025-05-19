cmake_minimum_required(VERSION 3.29)
project(portscanner)

set(CMAKE_CXX_STANDARD 20)

add_executable(portscanner main.cpp
        scanning/syn_scanner.h
        scanning/syn_scanner.cpp
        ip.h
        tcp.h
        random.h
        random.cpp
        utils.h
        utils.cpp
        scanning/scanning.h
        scanning/scanning.cpp
        cli.cpp
        cli.h
        arp.h
        scanning/arp_scanner.cpp
        scanning/arp_scanner.h)

cmake_minimum_required(VERSION 3.29)
project(portscanner)

set(CMAKE_CXX_STANDARD 20)

add_executable(portscanner main.cpp
        syn_scanner.h
        syn_scanner.cpp
        ip.h
        tcp.h
        random.h
        random.cpp
        utils.h
        utils.cpp)

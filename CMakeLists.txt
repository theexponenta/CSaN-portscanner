cmake_minimum_required(VERSION 3.29)
project(portscanner)

set(CMAKE_CXX_STANDARD 20)

add_executable(portscanner main.cpp)

target_link_libraries(portscanner ws2_32)

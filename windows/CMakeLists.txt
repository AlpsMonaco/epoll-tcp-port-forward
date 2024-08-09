cmake_minimum_required(VERSION 3.13)

project(wepoll-tcp-port-forward)

add_executable(tcp_port_forward tcp_port_forward.c wepoll/wepoll.c)

target_include_directories(tcp_port_forward PRIVATE wepoll)

target_link_libraries(tcp_port_forward PRIVATE ws2_32)
cmake_minimum_required(VERSION 3.13)

project(epoll-tcp-port-forward)

add_executable(tcp_port_forward tcp_port_forward.c session.c)

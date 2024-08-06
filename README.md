# epoll-tcp-port-forward
This is a program implements tcp port forwarding with epoll.  
This program is designed for those who wants to learn epoll with a practical project.  
It is not recommended to use it in a production environment.  
IPTABLES IS A BETTER CHOICE.


# Compile And Run
```shell
# need cmake to build this project
cd epoll-tcp-port-forward
cmake -B ./build .
cmake --build build --config MinSizeRel --target all
./build/tcp_port_forward 31212 127.0.0.1 22 # forward any data from 31212 to local 22 port
```

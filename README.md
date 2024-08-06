# epoll-tcp-port-forward
This program implements TCP port forwarding using epoll.  
It is designed for those who want to learn epoll through a practical project.  
Note: This program is not recommended for production use.  
For production, IPTABLES IS A BETTER CHOICE.  


# Compile And Run
```shell
# Requires cmake to build this project
cd epoll-tcp-port-forward
cmake -B ./build .
cmake --build build --config MinSizeRel --target all
./build/tcp_port_forward 31212 127.0.0.1 22 # Forward any data from port 31212 to local port 22
```

Alternatively, you can simply run:
```shell
gcc tcp_port_forward.c
./a.out 31212 127.0.0.1 22 # Forward any data from port 31212 to local port 22
```

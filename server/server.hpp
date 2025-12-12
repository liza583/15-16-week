#ifndef SERVER_HPP
#define SERVER_HPP

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdexcept>

void create_socket(int& socket_fd);
void bind_socket(int socket_fd, sockaddr_in& server_addr);
void listen_socket(int socket_fd);

#endif

#include "raw_socket.h"

#include <unistd.h>

using namespace edgeless::ttls;

int RawSocket::Close(int fd) {
  return close(fd);
}
int RawSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  return connect(sockfd, addr, addrlen);
}
ssize_t RawSocket::Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  return read(sockfd, buf, len);
}
ssize_t RawSocket::Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  return write(sockfd, buf, len);
}

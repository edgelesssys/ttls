#include "raw_socket.h"

#include <unistd.h>

using namespace edgeless::ttls;

int Close(int fd) {
  return close(fd);
}
int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  return connect(sockfd, addr, addrlen);
}
ssize_t Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  return read(sockfd, buf, len);
}
ssize_t Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  return write(sockfd, buf, len);
}

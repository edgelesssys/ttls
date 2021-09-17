#pragma once

#include "raw_socket.h"

namespace edgeless::ttls {

class LibcSocket : public RawSocket {
 public:
  int Close(int fd) override;
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override;
  int Bind(int sockfd, const sockaddr* addr, socklen_t addrlen) override;
  int Accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) override;
  ssize_t Recv(int sockfd, void* buf, size_t len, int flags) override;
  ssize_t Send(int sockfd, const void* buf, size_t len, int flags) override;
  int Shutdown(int sockfd, int how) override;
  int Getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** res) override;

  ssize_t Sendfile(int out_fd, int in_fd, off_t* offset, size_t count) override;
  ssize_t Recvfrom(int sockfd, void* __restrict__ buf, size_t len, int flags, struct sockaddr* __restrict__ address, socklen_t* __restrict__ address_len) override;
  ssize_t Writev(int fds, const struct iovec* iov, int iovcnt) override;
};

}  // namespace edgeless::ttls

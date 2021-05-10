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
};

}  // namespace edgeless::ttls

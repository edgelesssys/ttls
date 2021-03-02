#pragma once

#include "socket.h"

namespace edgeless::ttls {

class RawSocket : public Socket {
 public:
  int Close(int fd) override;
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override;
  ssize_t Recv(int sockfd, void* buf, size_t len, int flags) override;
  ssize_t Send(int sockfd, const void* buf, size_t len, int flags) override;
};

}  // namespace edgeless::ttls

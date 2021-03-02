#pragma once

#include <sys/socket.h>

#include <memory>

namespace edgeless::ttls {

class Socket {
 public:
  virtual ~Socket() = default;

  virtual int Close(int fd) = 0;
  virtual int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) = 0;
  virtual ssize_t Recv(int sockfd, void* buf, size_t len, int flags) = 0;
  virtual ssize_t Send(int sockfd, const void* buf, size_t len, int flags) = 0;
};

typedef std::shared_ptr<Socket> SocketPtr;

}  // namespace edgeless::ttls

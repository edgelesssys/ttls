#pragma once

#include <sys/socket.h>

#include <memory>

namespace edgeless::ttls {

class Socket {
 public:
  virtual ~Socket() = default;

  virtual int Close(int fd) = 0;
  virtual int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) = 0;
  virtual int Accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) = 0;
  virtual ssize_t Recv(int sockfd, void* buf, size_t len, int flags) = 0;
  virtual ssize_t Send(int sockfd, const void* buf, size_t len, int flags) = 0;
  virtual int Shutdown(int sockfd, int how) = 0;

  virtual ssize_t Sendfile(int out_fd, int in_fd, off_t* offset, size_t count) = 0;
  virtual ssize_t Recvfrom(int sockfd, void* __restrict__ buf, size_t len, int flags, struct sockaddr* __restrict__ address, socklen_t* __restrict__ address_len) = 0;
  virtual ssize_t Writev(int fds, const struct iovec* iov, int iovcnt) = 0;
};

typedef std::shared_ptr<Socket> SocketPtr;

}  // namespace edgeless::ttls

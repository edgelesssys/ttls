#pragma once

#include <unordered_map>

#include "mbedtls_context.h"
#include "socket.h"

namespace edgeless::ttls {
class MbedtlsSocket : public Socket {
 public:
  int Close(int fd) override;
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override;
  ssize_t Recv(int sockfd, void* buf, size_t len, int flags) override;
  ssize_t Send(int sockfd, const void* buf, size_t len, int flags) override;

 private:
  std::unordered_map<int, MbedtlsContext> m;

  template <typename TF, typename... Args>
  decltype(auto) execAndCheckResult(TF&& f, Args... a);
};

}  // namespace edgeless::ttls

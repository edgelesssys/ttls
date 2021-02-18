#pragma once

#include <unordered_map>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "socket.h"

namespace edgeless::ttls {
class MbedtlsSocket : public Socket {
 public:
  MbedtlsSocket();
  ~MbedtlsSocket() override;

  int Close(int sockfd) override;
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override;
  ssize_t Recv(int sockfd, void* buf, size_t len, int flags) override;
  ssize_t Send(int sockfd, const void* buf, size_t len, int flags) override;

 private:
  std::unordered_map<int, std::pair<mbedtls_ssl_context, mbedtls_net_context>> contexts_;

  mbedtls_ssl_config conf_;
  mbedtls_x509_crt cacert_;
  mbedtls_ctr_drbg_context ctr_drbg_;
  mbedtls_entropy_context entropy_;
};

}  // namespace edgeless::ttls

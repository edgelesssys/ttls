#pragma once

#include <unordered_map>

#include "mbedtls/certs.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"
#include "socket.h"

namespace edgeless::ttls {
class MbedtlsSocket : public Socket {
 public:
  MbedtlsSocket();
  ~MbedtlsSocket();

  int Close(int sockfd) override;
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override;
  ssize_t Recv(int sockfd, void* buf, size_t len, int flags) override;
  ssize_t Send(int sockfd, const void* buf, size_t len, int flags) override;

 private:
  std::unordered_map<int, std::pair<mbedtls_ssl_context, mbedtls_net_context>> contexts_;

  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;
};

}  // namespace edgeless::ttls

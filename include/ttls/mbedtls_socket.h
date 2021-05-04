#pragma once

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>

#include <mutex>
#include <unordered_map>

#include "socket.h"

namespace edgeless::ttls {

class MbedtlsSocket : public Socket {
 public:
  MbedtlsSocket();
  MbedtlsSocket(const SocketPtr& sock, bool req_client_auth);
  ~MbedtlsSocket() override;

  int Close(int sockfd) override;
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override;
  int Accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) override;
  virtual int Accept(int sockfd, const std::string& ca_crt,
                     const std::string& sever_crt, const std::string& sever_key);
  virtual int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen, const std::string& hostname,
                      const std::string& ca_crt, const std::string& client_crt, const std::string& client_key);
  ssize_t Recv(int sockfd, void* buf, size_t len, int flags) override;
  ssize_t Send(int sockfd, const void* buf, size_t len, int flags) override;
  int Shutdown(int sockfd, int how) override;

 private:
  static int sock_net_send(void* ctx, const unsigned char* buf, size_t len);
  static int sock_net_recv(void* ctx, unsigned char* buf, size_t len);
  struct Context {
    mbedtls_ssl_config conf{};
    mbedtls_ssl_context ssl{};
    mbedtls_net_context net{};
    mbedtls_x509_crt cacerts{};
    mbedtls_x509_crt clicert{};
    mbedtls_pk_context pkey{};
    SocketPtr sock{};
  };
  std::mutex mtx_;
  std::unordered_map<int, Context> contexts_;
  SocketPtr sock_;

  mbedtls_ctr_drbg_context ctr_drbg_;
  mbedtls_entropy_context entropy_;
  bool req_client_auth_;
};

typedef std::shared_ptr<MbedtlsSocket> MbedtlsSockPtr;

}  // namespace edgeless::ttls

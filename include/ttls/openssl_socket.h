#pragma once

#include <openssl/ssl.h>

#include <mutex>
#include <unordered_map>

#include "socket.h"

namespace edgeless::ttls {

class OpensslSocket : public Socket {
 public:
  OpensslSocket();
  OpensslSocket(SocketPtr sock, bool req_client_auth);
  ~OpensslSocket() override;

  int Close(int sockfd) override;
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override;
  int Accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) override;

  // accepts a new connection from sockfd and establishes a tls connection on the returned fd
  virtual int Accept(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags, const std::string& ca_crt,
                     const std::string& server_crt, const std::string& server_key, bool client_auth);
  virtual int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen, const std::string& hostname,
                      const std::string& ca_crt, const std::string& client_crt, const std::string& client_key);
  ssize_t Recv(int sockfd, void* buf, size_t len, int flags) override;
  ssize_t Send(int sockfd, const void* buf, size_t len, int flags) override;
  int Shutdown(int sockfd, int how) override;

 private:
  static const BIO_METHOD* BioMethod();
  static int BioRead(BIO* b, char* buf, int len);
  static int BioWrite(BIO* b, const char* buf, int len);
  static long BioCtrl(BIO* b, int cmd, long num, void* ptr);  // NOLINT
  struct Context {
    SSL_CTX* ssl_ctx{};
    SSL* ssl{};
    int fd{-1};
    SocketPtr sock{};
    std::mutex mtx;
  };
  std::mutex mtx_;
  std::unordered_map<int, Context> contexts_;
  SocketPtr sock_;

  bool req_client_auth_;
};

typedef std::shared_ptr<OpensslSocket> OpensslSockPtr;

}  // namespace edgeless::ttls

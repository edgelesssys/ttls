#include "mbedtls_socket.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

#include <array>
#include <cassert>
#include <stdexcept>
#include <string>
#include <system_error>

#include "mbedtls/error.h"
#include "mbedtls/ssl_internal.h"

using namespace edgeless::ttls;

static int CheckResult(const int ret, const int default_errno = EPROTO) {
  using namespace std::string_literals;
  if (ret >= 0) {
    return ret;
  }
  if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    return 0;
  std::array<char, 100> buf{};
  mbedtls_strerror(ret, buf.data(), buf.size());
  switch (ret) {
    case MBEDTLS_ERR_SSL_WANT_WRITE:
    case MBEDTLS_ERR_SSL_WANT_READ:
      throw std::system_error(EAGAIN, std::generic_category(), "mbedtls: "s + buf.data());
    case MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO:
    case MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE:
    case MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE:
    case MBEDTLS_ERR_SSL_CONN_EOF:
      throw std::system_error(ECONNABORTED, std::generic_category(), "mbedtls: "s + buf.data());
    default:
      throw std::system_error(default_errno, std::generic_category(), "mbedtls: "s + buf.data());
  }
}

MbedtlsSocket::MbedtlsSocket()
    : ctr_drbg_{}, entropy_{}, req_client_auth_(false) {
}

MbedtlsSocket::MbedtlsSocket(SocketPtr sock, bool req_client_auth)
    : sock_(std::move(sock)), ctr_drbg_{}, entropy_{}, req_client_auth_(req_client_auth) {
  assert(sock_);
  mbedtls_ctr_drbg_init(&ctr_drbg_);
  mbedtls_entropy_init(&entropy_);

  CheckResult(mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_,
                                    nullptr,
                                    0));
}

MbedtlsSocket::~MbedtlsSocket() {
  mbedtls_ctr_drbg_free(&ctr_drbg_);
  mbedtls_entropy_free(&entropy_);
}

int MbedtlsSocket::sock_net_send(void* ctx, const unsigned char* buf, size_t len) {
  const auto& context = *static_cast<Context*>(ctx);
  if (context.net.fd < 0)
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  const auto ret = context.sock->Send(context.net.fd, buf, len, 0);
  if (ret >= 0)
    return ret;
  switch (errno) {
    case EAGAIN:
    case EINTR:
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    case EPIPE:
    case ECONNRESET:
      return MBEDTLS_ERR_NET_CONN_RESET;
  }
  return MBEDTLS_ERR_NET_SEND_FAILED;
}

int MbedtlsSocket::sock_net_recv(void* ctx, unsigned char* buf, size_t len) {
  const auto& context = *static_cast<Context*>(ctx);
  if (context.net.fd < 0)
    return MBEDTLS_ERR_NET_INVALID_CONTEXT;
  const auto ret = context.sock->Recv(context.net.fd, buf, len, 0);
  if (ret >= 0)
    return ret;
  switch (errno) {
    case EAGAIN:
      return MBEDTLS_ERR_SSL_WANT_READ;
    case EINTR:
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    case EPIPE:
    case ECONNRESET:
      return MBEDTLS_ERR_NET_CONN_RESET;
  }
  return MBEDTLS_ERR_NET_RECV_FAILED;
}

/**
 * Close fd and clean up context
 */
int MbedtlsSocket::Close(int sockfd) {
  std::lock_guard<std::mutex> lock(mtx_);
  auto& ctx = contexts_.at(sockfd);

  mbedtls_x509_crt_free(&ctx.clicert);
  mbedtls_pk_free(&ctx.pkey);
  mbedtls_ssl_config_free(&ctx.conf);
  mbedtls_x509_crt_free(&ctx.cacerts);
  mbedtls_ssl_free(&ctx.ssl);

  if (sock_->Close(ctx.net.fd) != 0) {
    throw std::runtime_error("close failed");
  }
  contexts_.erase(sockfd);
  return 0;
}

/*
* Gracefully shutdown TLS and TCP connection
*/
int MbedtlsSocket::Shutdown(int sockfd, int how) {
  std::lock_guard<std::mutex> lock(mtx_);
  auto& ctx = contexts_.at(sockfd);

  CheckResult(mbedtls_ssl_close_notify(&ctx.ssl));
  if (sock_->Shutdown(ctx.net.fd, how) != 0) {
    throw std::runtime_error("shutdown failed");
  }
  return 0;
}

int MbedtlsSocket::Connect(int /*sockfd*/, const sockaddr* /*addr*/, socklen_t /*addrlen*/) {
  throw std::runtime_error("no crt provided");
  return -1;
}

int MbedtlsSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen, const std::string& hostname, const std::string& ca_crt,
                           const std::string& client_crt, const std::string& client_key) {
  const auto ret = [&] {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.try_emplace(sockfd);
  }();

  if (!ret.second)
    throw std::system_error(EISCONN, std::system_category(), __func__);
  auto& ctx = ret.first->second;

  ctx.sock = sock_;
  mbedtls_net_init(&ctx.net);
  mbedtls_ssl_init(&ctx.ssl);
  mbedtls_ssl_config_init(&ctx.conf);
  mbedtls_x509_crt_init(&ctx.cacerts);

  CheckResult(mbedtls_ssl_config_defaults(&ctx.conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT));
  mbedtls_ssl_conf_rng(&ctx.conf, mbedtls_ctr_drbg_random, &ctr_drbg_);

  CheckResult(mbedtls_x509_crt_parse(&ctx.cacerts, reinterpret_cast<const unsigned char*>(ca_crt.data()), ca_crt.size() + 1));
  mbedtls_ssl_conf_ca_chain(&ctx.conf, &ctx.cacerts, nullptr);
  mbedtls_ssl_conf_authmode(&ctx.conf, MBEDTLS_SSL_VERIFY_REQUIRED);

  ctx.net.fd = sockfd;

  CheckResult(mbedtls_ssl_setup(&ctx.ssl, &ctx.conf));

  // Client Auth
  if (!client_crt.empty() && !client_key.empty()) {
    CheckResult(mbedtls_x509_crt_parse(&ctx.clicert,
                                       reinterpret_cast<const unsigned char*>(client_crt.data()),
                                       client_crt.size() + 1));
    CheckResult(mbedtls_pk_parse_key(&ctx.pkey,
                                     reinterpret_cast<const unsigned char*>(client_key.data()),
                                     client_key.size() + 1, nullptr, 0));
    CheckResult(mbedtls_ssl_conf_own_cert(&ctx.conf, &ctx.clicert, &ctx.pkey));
  }

  if (!hostname.empty())
    CheckResult(mbedtls_ssl_set_hostname(&ctx.ssl, hostname.data()));

  if (sock_->Connect(ctx.net.fd, addr, addrlen) && errno != EINPROGRESS) {
    throw std::system_error(errno, std::generic_category());
  }

  mbedtls_ssl_set_bio(&ctx.ssl, &ctx, sock_net_send, sock_net_recv, nullptr);

  pollfd pfd{ctx.net.fd, POLLOUT | POLLIN, 0};
  int re = -1;
  do {
    if (poll(&pfd, 1, -1) < 0)
      throw std::runtime_error("socket unavailable");

    re = mbedtls_ssl_handshake(&ctx.ssl);
    if (re == MBEDTLS_ERR_SSL_WANT_READ || re == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }
    if (re < 0) {                             // any unhandled handshake error
      this->Shutdown(ctx.net.fd, SHUT_RDWR);  // shutdown connection before throwing
    }
    CheckResult(re, ECONNREFUSED);
  } while (re != 0);

  return 0;
}

ssize_t MbedtlsSocket::Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  auto& ctx = [&]() -> auto& {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.at(sockfd);
  }
  ();
  return CheckResult(mbedtls_ssl_read(&ctx.ssl, static_cast<unsigned char*>(buf), len));
}

ssize_t MbedtlsSocket::Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  auto& ctx = [&]() -> auto& {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.at(sockfd);
  }
  ();
  return CheckResult(mbedtls_ssl_write(&ctx.ssl, static_cast<const unsigned char*>(buf), len));
}

int MbedtlsSocket::Accept4(int /*sockfd*/, sockaddr* /*addr*/, socklen_t* /*addrlen*/, int /*flags*/) {
  throw std::runtime_error("no crt provided");
}

int MbedtlsSocket::Accept(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags, const std::string& ca_crt,
                          const std::string& server_crt, const std::string& server_key, const bool client_auth) {
  const int connection_fd = sock_->Accept4(sockfd, addr, addrlen, flags);
  if (connection_fd == -1)
    throw std::system_error(errno, std::generic_category());
  const auto ret = [&] {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.try_emplace(connection_fd);
  }();

  if (!ret.second)
    throw std::system_error(EISCONN, std::system_category(), __func__);
  auto& ctx = ret.first->second;
  ctx.sock = sock_;
  ctx.net.fd = connection_fd;

  CheckResult(mbedtls_x509_crt_parse(&ctx.cacerts,
                                     reinterpret_cast<const unsigned char*>(ca_crt.data()),
                                     ca_crt.size() + 1));
  CheckResult(mbedtls_x509_crt_parse(&ctx.clicert,
                                     reinterpret_cast<const unsigned char*>(server_crt.data()),
                                     server_crt.size() + 1));
  CheckResult(mbedtls_pk_parse_key(&ctx.pkey,
                                   reinterpret_cast<const unsigned char*>(server_key.data()),
                                   server_key.size() + 1, nullptr, 0));

  CheckResult(mbedtls_ssl_config_defaults(&ctx.conf, MBEDTLS_SSL_IS_SERVER,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT));

  mbedtls_ssl_conf_rng(&ctx.conf, mbedtls_ctr_drbg_random, &ctr_drbg_);
  mbedtls_ssl_conf_ca_chain(&ctx.conf, &ctx.cacerts, nullptr);

  if (req_client_auth_ && client_auth)
    mbedtls_ssl_conf_authmode(&ctx.conf, MBEDTLS_SSL_VERIFY_REQUIRED);

  CheckResult(mbedtls_ssl_conf_own_cert(&ctx.conf, &ctx.clicert, &ctx.pkey));
  CheckResult(mbedtls_ssl_setup(&ctx.ssl, &ctx.conf));

  mbedtls_ssl_set_bio(&ctx.ssl, &ctx, sock_net_send, sock_net_recv, nullptr);

  pollfd pfd{ctx.net.fd, POLLOUT | POLLIN, 0};
  int re = -1;
  do {
    if (poll(&pfd, 1, -1) < 0)
      throw std::runtime_error("socket unavailable");

    re = mbedtls_ssl_handshake(&ctx.ssl);

    if (re == MBEDTLS_ERR_SSL_WANT_READ || re == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }
    if (re < 0) {               // any unhandled handshake error
      this->Close(ctx.net.fd);  // close connection before throwing
    }
    CheckResult(re, ECONNABORTED);
  } while (re != 0);

  return ctx.net.fd;
}

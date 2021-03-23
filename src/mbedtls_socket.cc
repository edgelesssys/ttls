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

using namespace edgeless::ttls;

static int CheckResult(int ret) {
  using namespace std::string_literals;
  if (ret < 0) {
    std::array<char, 100> buf{};
    mbedtls_strerror(ret, buf.data(), buf.size());
    throw std::runtime_error("mbedtls: "s + buf.data());
  }
  return ret;
}

MbedtlsSocket::MbedtlsSocket()
    : ctr_drbg_{}, entropy_{} {
}

MbedtlsSocket::MbedtlsSocket(const SocketPtr& sock)
    : sock_(sock), ctr_drbg_{}, entropy_{} {
  assert(sock);
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
  return MBEDTLS_ERR_NET_SEND_FAILED;
}

/**
 * Close fd and clean up context
 */
int MbedtlsSocket::Close(int sockfd) {
  std::lock_guard<std::mutex> lock(mtx_);
  auto& ctx = contexts_.at(sockfd);

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

int MbedtlsSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
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

  CheckResult(mbedtls_x509_crt_parse_file(ctx.cacerts, "ca.crt"));
  mbedtls_ssl_conf_ca_chain(&ctx.conf, &ctx.cacerts, nullptr);
  mbedtls_ssl_conf_authmode(&ctx.conf, MBEDTLS_SSL_VERIFY_REQUIRED);

  ctx.net.fd = sockfd;

  CheckResult(mbedtls_ssl_setup(&ctx.ssl, &ctx.conf));
  CheckResult(mbedtls_ssl_set_hostname(&ctx.ssl, "localhost"));  // TODO: propably parse sockaddr or new param from dispatcher

  if (sock_->Connect(ctx.net.fd, addr, addrlen) && errno != EINPROGRESS) {
    throw std::runtime_error("connect failed");
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
    CheckResult(re);
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

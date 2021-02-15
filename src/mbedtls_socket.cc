#include "mbedtls_socket.h"

#include <netdb.h>

#include <stdexcept>

using namespace edgeless::ttls;

template <typename TF, typename... Args>
decltype(auto) MbedtlsSocket::execAndCheckResult(TF&& f, Args... args) {
  int ret = f(args...);
  if (ret < 0) {
    throw std::runtime_error("error");
  }
  return ret;
}

int MbedtlsSocket::Close(int sockfd) {
  auto ctx = m.at(sockfd);
  execAndCheckResult(mbedtls_ssl_close_notify, &ctx.ssl);
  m.erase(sockfd);
  return 0;
}

int MbedtlsSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  auto ret = m.try_emplace(sockfd, MbedtlsContext{});
  auto ctx = ret.first->second;

  // extract hostname and port of sockaddr
  std::string hbuf = std::string(NI_MAXHOST, ' ');
  std::string sbuf = std::string(NI_MAXSERV, ' ');
  getnameinfo(addr, addrlen, &hbuf[0], NI_MAXHOST, &sbuf[0],
              NI_MAXSERV, static_cast<unsigned int>(NI_NUMERICHOST) | static_cast<unsigned int>(NI_NUMERICSERV));

  execAndCheckResult(mbedtls_net_connect, &ctx.server_fd, &hbuf[0], &sbuf[0], MBEDTLS_NET_PROTO_TCP);

  execAndCheckResult(mbedtls_ssl_config_defaults, &ctx.conf,
                     MBEDTLS_SSL_IS_CLIENT,
                     MBEDTLS_SSL_TRANSPORT_STREAM,
                     MBEDTLS_SSL_PRESET_DEFAULT);

  /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
  mbedtls_ssl_conf_authmode(&ctx.conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain(&ctx.conf, &ctx.cacert, nullptr);
  mbedtls_ssl_conf_rng(&ctx.conf, mbedtls_ctr_drbg_random, &ctx.ctr_drbg);
  //mbedtls_ssl_conf_dbg(&ctx->conf, my_debug, stdout);
  execAndCheckResult(mbedtls_ssl_setup, &ctx.ssl, &ctx.conf);
  execAndCheckResult(mbedtls_ssl_set_hostname, &ctx.ssl, &hbuf[0]);
  mbedtls_ssl_set_bio(&ctx.ssl, &ctx.server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
  execAndCheckResult(mbedtls_ssl_handshake, &ctx.ssl);
  execAndCheckResult(mbedtls_ssl_get_verify_result, &ctx.ssl);

  return 0;
}

ssize_t MbedtlsSocket::Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  auto ctx = m.at(sockfd);
  int ret = execAndCheckResult(mbedtls_ssl_read, &ctx.ssl, static_cast<unsigned char*>(buf), len);
  return ret;
}

ssize_t MbedtlsSocket::Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  auto ctx = m.at(sockfd);
  int ret = execAndCheckResult(mbedtls_ssl_write, &ctx.ssl, static_cast<const unsigned char*>(buf), len);
  return ret;
}

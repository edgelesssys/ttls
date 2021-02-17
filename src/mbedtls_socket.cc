#include "mbedtls_socket.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#include <stdexcept>
#include <string>

using namespace edgeless::ttls;

static int CheckResult(int ret) {
  constexpr size_t kBufferSize = 100;
  using namespace std::string_literals;
  if (ret < 0) {
    std::array<char, kBufferSize> buf{};
    mbedtls_strerror(ret, buf.data(), buf.size());
    throw std::runtime_error("mbedtls: "s + buf.data());
  }
  return ret;
}

int MbedtlsSocket::Close(int sockfd) {
  auto& ctx = contexts_.at(sockfd);
  CheckResult(mbedtls_ssl_close_notify(&ctx.ssl));
  contexts_.erase(sockfd);
  return 0;
}

int MbedtlsSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  auto ret = contexts_.try_emplace(sockfd, MbedtlsContext{});
  auto& ctx = ret.first->second;
  ctx.server_fd.fd = sockfd;

  CheckResult(mbedtls_ctr_drbg_seed(&ctx.ctr_drbg, mbedtls_entropy_func, &ctx.entropy,  //TODO: CHECK OUTPUT
                                    nullptr,
                                    0));
  CheckResult(mbedtls_ssl_config_defaults(&ctx.conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT));
  mbedtls_ssl_conf_rng(&ctx.conf, mbedtls_ctr_drbg_random, &ctx.ctr_drbg);

  // std::string cert = MbedtlsContext::readCert("test-ca-sha256.crt");
  // CheckResult(mbedtls_x509_crt_parse(&ctx.cacert, (const unsigned char*)cert.c_str(),
  //                                    cert.size()));

  CheckResult(mbedtls_x509_crt_parse_file(&ctx.cacert, "test-ca-sha256.crt"));
  mbedtls_ssl_conf_authmode(&ctx.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&ctx.conf, &ctx.cacert, nullptr);

  CheckResult(mbedtls_ssl_setup(&ctx.ssl, &ctx.conf));
  CheckResult(mbedtls_ssl_set_hostname(&ctx.ssl, "localhost"));

  CheckResult(connect(sockfd, addr, addrlen));  // connection failed -> exit code 6

  mbedtls_ssl_set_bio(&ctx.ssl, &ctx.server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
  CheckResult(mbedtls_ssl_handshake(&ctx.ssl));

  return 0;
}

ssize_t MbedtlsSocket::Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  auto& ctx = contexts_.at(sockfd);
  return CheckResult(mbedtls_ssl_read(&ctx.ssl, static_cast<unsigned char*>(buf), len));
}

ssize_t MbedtlsSocket::Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  auto& ctx = contexts_.at(sockfd);
  return CheckResult(mbedtls_ssl_write(&ctx.ssl, static_cast<const unsigned char*>(buf), len));
}

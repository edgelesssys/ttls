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

MbedtlsSocket::MbedtlsSocket()
    : conf{}, cacert{}, ctr_drbg{}, entropy{} {
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  CheckResult(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,  //TODO: CHECK OUTPUT
                                    nullptr,
                                    0));
  CheckResult(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT));

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  CheckResult(mbedtls_x509_crt_parse_file(&cacert, "test-ca-sha256.crt"));
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, nullptr);
}

MbedtlsSocket::~MbedtlsSocket() {
  mbedtls_x509_crt_free(&cacert);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

int MbedtlsSocket::Close(int sockfd) {
  auto& ret = contexts_.at(sockfd);
  auto& ssl = ret.first;
  auto& server_fd = ret.second;

  CheckResult(mbedtls_ssl_close_notify(&ssl));

  mbedtls_ssl_free(&ssl);
  mbedtls_net_free(&server_fd);
  contexts_.erase(sockfd);
  return 0;
}

int MbedtlsSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  auto ret = contexts_.try_emplace(sockfd, std::make_pair(mbedtls_ssl_context{}, mbedtls_net_context{}));
  auto& ssl = ret.first->second.first;
  auto& server_fd = ret.first->second.second;

  mbedtls_ssl_init(&ssl);
  mbedtls_net_init(&server_fd);
  server_fd.fd = sockfd;

  // std::string cert = MbedtlsContext::readCert("test-ca-sha256.crt");
  // CheckResult(mbedtls_x509_crt_parse(&ctx.cacert, (const unsigned char*)cert.c_str(),
  //                                    cert.size()));

  CheckResult(mbedtls_ssl_setup(&ssl, &conf));
  CheckResult(mbedtls_ssl_set_hostname(&ssl, "localhost"));

  CheckResult(connect(server_fd.fd, addr, addrlen));  // connection failed -> exit code 6

  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
  CheckResult(mbedtls_ssl_handshake(&ssl));

  return 0;
}

ssize_t MbedtlsSocket::Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  auto& ssl = contexts_.at(sockfd).first;
  return CheckResult(mbedtls_ssl_read(&ssl, static_cast<unsigned char*>(buf), len));
}

ssize_t MbedtlsSocket::Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  auto& ssl = contexts_.at(sockfd).first;
  return CheckResult(mbedtls_ssl_write(&ssl, static_cast<const unsigned char*>(buf), len));
}

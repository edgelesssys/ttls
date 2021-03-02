#include "mbedtls_socket.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#include <array>
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
    : conf_{}, cacert_{}, ctr_drbg_{}, entropy_{} {
  mbedtls_ssl_config_init(&conf_);
  mbedtls_x509_crt_init(&cacert_);
  mbedtls_ctr_drbg_init(&ctr_drbg_);
  mbedtls_entropy_init(&entropy_);

  CheckResult(mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_,
                                    nullptr,
                                    0));
  CheckResult(mbedtls_ssl_config_defaults(&conf_, MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT));

  mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &ctr_drbg_);
  CheckResult(mbedtls_x509_crt_parse_file(&cacert_, "ca.crt"));
  mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conf_, &cacert_, nullptr);
}

MbedtlsSocket::~MbedtlsSocket() {
  mbedtls_x509_crt_free(&cacert_);
  mbedtls_ssl_config_free(&conf_);
  mbedtls_ctr_drbg_free(&ctr_drbg_);
  mbedtls_entropy_free(&entropy_);
}

int MbedtlsSocket::Close(int sockfd) {
  std::lock_guard<std::mutex> lock(mtx_);
  auto& [ssl, server_fd] = contexts_.at(sockfd);

  CheckResult(mbedtls_ssl_close_notify(&ssl));

  mbedtls_ssl_free(&ssl);
  mbedtls_net_free(&server_fd);
  contexts_.erase(sockfd);
  return 0;
}

int MbedtlsSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  const auto ret = [&] {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.try_emplace(sockfd);
  }();

  if (!ret.second)
    throw std::system_error(EISCONN, std::system_category(), __func__);
  auto& [ssl, server_fd] = ret.first->second;

  mbedtls_ssl_init(&ssl);
  mbedtls_net_init(&server_fd);
  server_fd.fd = sockfd;

  CheckResult(mbedtls_ssl_setup(&ssl, &conf_));
  CheckResult(mbedtls_ssl_set_hostname(&ssl, "localhost"));

  connect(server_fd.fd, addr, addrlen);

  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);

  int re = -1;
  do {
    re = mbedtls_ssl_handshake(&ssl);
    if (re == MBEDTLS_ERR_SSL_WANT_READ || re == MBEDTLS_ERR_SSL_WANT_WRITE) {
      continue;
    }
    CheckResult(re);
  } while (re != 0);

  return 0;
}

ssize_t MbedtlsSocket::Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  auto& ssl = [&]() -> auto& {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.at(sockfd).first;
  }
  ();

  int ret = -1;
  do {
    ret = mbedtls_ssl_read(&ssl, static_cast<unsigned char*>(buf), len);
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      break;
    }
  } while (true);

  CheckResult(ret);
  return ret;
}

ssize_t MbedtlsSocket::Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  auto& ssl = [&]() -> auto& {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.at(sockfd).first;
  }
  ();
  return CheckResult(mbedtls_ssl_write(&ssl, static_cast<const unsigned char*>(buf), len));
}

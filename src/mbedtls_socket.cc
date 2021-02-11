#include "mbedtls_socket.h"

#include <mbedtls/ssl.h>
#include <netdb.h>
#include <sys/socket.h>

#include <fstream>
#include <sstream>
#include <string>

using namespace edgeless::ttls;

int MbedtlsSocket::Close(int sockfd) {
  MbedtlsContext* ctx = m[sockfd];
  mbedtls_ssl_close_notify(&ctx->ssl);
  m.erase(sockfd);
  return -1;
}

int MbedtlsSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  auto ctx = m.insert({sockfd, new MbedtlsContext()}).first->second;

  // extract hostname and port of sockaddr
  auto hbuf = new std::string[NI_MAXHOST];
  auto sbuf = new std::string[NI_MAXSERV];
  getnameinfo(addr, addrlen, hbuf->data(), NI_MAXHOST, sbuf->data(),
              NI_MAXSERV, static_cast<unsigned int>(NI_NUMERICHOST) | static_cast<unsigned int>(NI_NUMERICSERV));

  mbedtls_net_connect(&ctx->server_fd, hbuf->data(), sbuf->data(), MBEDTLS_NET_PROTO_TCP);

  mbedtls_ssl_config_defaults(&ctx->conf,
                              MBEDTLS_SSL_IS_CLIENT,
                              MBEDTLS_SSL_TRANSPORT_STREAM,
                              MBEDTLS_SSL_PRESET_DEFAULT);

  /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
  mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->cacert, nullptr);
  mbedtls_ssl_conf_rng(&ctx->conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
  //mbedtls_ssl_conf_dbg(&ctx->conf, my_debug, stdout);
  mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
  mbedtls_ssl_set_hostname(&ctx->ssl, hbuf->data());
  mbedtls_ssl_set_bio(&ctx->ssl, &ctx->server_fd, mbedtls_net_send, mbedtls_net_recv, nullptr);
  mbedtls_ssl_handshake(&ctx->ssl);
  mbedtls_ssl_get_verify_result(&ctx->ssl);
  return -1;
}

ssize_t MbedtlsSocket::Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  auto ctx = m[sockfd];
  mbedtls_ssl_read(&ctx->ssl, static_cast<unsigned char*>(buf), len);
  return -1;
}

ssize_t MbedtlsSocket::Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  auto ctx = m[sockfd];
  mbedtls_ssl_write(&ctx->ssl, static_cast<const unsigned char*>(buf), len);
  return -1;
}

MbedtlsContext::MbedtlsContext() : server_fd{}, ssl{}, conf{}, cacert{}, ctr_drbg{}, entropy{} {
  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        nullptr,
                        0);

  std::string cert = readCert("cert.pem");
  mbedtls_x509_crt_parse(&cacert, (const unsigned char*)cert.c_str(),
                         sizeof(cert.c_str()));
}

MbedtlsContext::~MbedtlsContext() {
  mbedtls_net_free(&server_fd);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

std::string MbedtlsContext::readCert(const char* filename) {
  std::ifstream infile(filename);
  auto cert = std::ostringstream{};
  if (infile) {
    cert << infile.rdbuf();
    infile.close();
    return (cert.str());
  }
  return "";
}

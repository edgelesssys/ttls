#include "openssl_socket.h"

#include <openssl/err.h>
#include <poll.h>

#include <array>
#include <cassert>
#include <stdexcept>
#include <string>
#include <system_error>

using namespace edgeless::ttls;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

static int CheckResult(const SSL* ssl, const int ret, const int default_errno = EPROTO) {
  using namespace std::string_literals;
  if (ret > 0) {
    return ret;
  }
  switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_ZERO_RETURN:
      return 0;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
      throw std::system_error(EAGAIN, std::generic_category(), "openssl: want read/write");
    case SSL_ERROR_SYSCALL:
      throw std::system_error(errno ? errno : default_errno, std::generic_category(), "openssl: syscall");
  }

  std::array<char, 256> buf{};
  ERR_error_string_n(ERR_get_error(), buf.data(), buf.size());
  throw std::system_error(default_errno, std::generic_category(), "openssl: "s + buf.data());
}

static void AddCaCerts(const SSL_CTX* ctx, const std::string& ca_pem) {
  const BioPtr bio(BIO_new_mem_buf(ca_pem.data(), static_cast<int>(ca_pem.size())), BIO_free);
  if (!bio)
    throw std::runtime_error("openssl: cannot create CA BIO");
  const X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
  if (!cert)
    throw std::runtime_error("openssl: cannot parse CA certificate");
  if (X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), cert.get()) != 1)
    throw std::runtime_error("openssl: cannot add CA certificate");
}

static void LoadCertificate(SSL_CTX* ctx, const std::string& cert_pem) {
  const BioPtr bio(BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size())), BIO_free);
  if (!bio)
    throw std::runtime_error("openssl: cannot create certificate BIO");
  const X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
  if (!cert)
    throw std::runtime_error("openssl: cannot parse certificate");
  if (SSL_CTX_use_certificate(ctx, cert.get()) != 1)
    throw std::runtime_error("openssl: cannot load certificate");
}

static void LoadPrivateKey(SSL_CTX* ctx, const std::string& key_pem) {
  const BioPtr bio(BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size())), BIO_free);
  if (!bio)
    throw std::runtime_error("openssl: cannot create key BIO");
  const PkeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
  if (!key)
    throw std::runtime_error("openssl: cannot parse private key");
  if (SSL_CTX_use_PrivateKey(ctx, key.get()) != 1)
    throw std::runtime_error("openssl: cannot load private key");
  if (SSL_CTX_check_private_key(ctx) != 1)
    throw std::runtime_error("openssl: private key does not match certificate");
}

OpensslSocket::OpensslSocket()
    : req_client_auth_(false) {
}

OpensslSocket::OpensslSocket(SocketPtr sock, bool req_client_auth)
    : sock_(std::move(sock)), req_client_auth_(req_client_auth) {
  assert(sock_);
}

OpensslSocket::~OpensslSocket() = default;

const BIO_METHOD* OpensslSocket::BioMethod() {
  static const BIO_METHOD* method = [] {
    BIO_METHOD* const m = BIO_meth_new(BIO_TYPE_NONE, "ttls");
    if (!m)
      throw std::runtime_error("openssl: cannot create BIO method");
    BIO_meth_set_read(m, BioRead);
    BIO_meth_set_write(m, BioWrite);
    BIO_meth_set_ctrl(m, BioCtrl);
    return m;
  }();
  return method;
}

int OpensslSocket::BioRead(BIO* b, char* buf, int len) {
  BIO_clear_retry_flags(b);
  const auto& context = *static_cast<Context*>(BIO_get_data(b));
  if (context.fd < 0)
    return 0;
  const auto ret = context.sock->Recv(context.fd, buf, static_cast<size_t>(len), 0);
  if (ret >= 0)
    return static_cast<int>(ret);
  switch (errno) {
    case EAGAIN:
    case EINTR:
      BIO_set_retry_read(b);
      return -1;
    default:
      return -1;
  }
}

int OpensslSocket::BioWrite(BIO* b, const char* buf, int len) {
  BIO_clear_retry_flags(b);
  const auto& context = *static_cast<Context*>(BIO_get_data(b));
  if (context.fd < 0)
    return 0;
  const auto ret = context.sock->Send(context.fd, buf, static_cast<size_t>(len), 0);
  if (ret >= 0)
    return ret;
  switch (errno) {
    case EAGAIN:
    case EINTR:
      BIO_set_retry_write(b);
      return -1;
    default:
      return -1;
  }
}

long OpensslSocket::BioCtrl(BIO* /*b*/, int cmd, long /*num*/, void* /*ptr*/) {  // NOLINT
  return cmd == BIO_CTRL_FLUSH ? 1 : 0;
}

/**
 * Close fd and clean up context
 */
int OpensslSocket::Close(int sockfd) {
  std::lock_guard<std::mutex> lock(mtx_);
  auto& ctx = contexts_.at(sockfd);

  SSL_free(ctx.ssl);
  SSL_CTX_free(ctx.ssl_ctx);

  if (sock_->Close(ctx.fd) != 0) {
    throw std::runtime_error("close failed");
  }
  contexts_.erase(sockfd);
  return 0;
}

/*
 * Gracefully shutdown TLS and TCP connection
 */
int OpensslSocket::Shutdown(int sockfd, int how) {
  std::lock_guard<std::mutex> lock(mtx_);
  auto& ctx = contexts_.at(sockfd);

  if (SSL_shutdown(ctx.ssl) < 0 || sock_->Shutdown(ctx.fd, how) != 0) {
    throw std::runtime_error("shutdown failed");
  }
  return 0;
}

int OpensslSocket::Connect(int /*sockfd*/, const sockaddr* /*addr*/, socklen_t /*addrlen*/) {
  throw std::runtime_error("no crt provided");
}

int OpensslSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen, const std::string& hostname, const std::string& ca_crt,
                           const std::string& client_crt, const std::string& client_key) {
  const auto ret = [&] {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.try_emplace(sockfd);
  }();

  if (!ret.second)
    throw std::system_error(EISCONN, std::system_category(), __func__);
  auto& ctx = ret.first->second;

  ctx.sock = sock_;
  ctx.fd = sockfd;

  ctx.ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx.ssl_ctx)
    throw std::runtime_error("openssl: cannot create client context");

  SSL_CTX_set_verify(ctx.ssl_ctx, SSL_VERIFY_PEER, nullptr);
  AddCaCerts(ctx.ssl_ctx, ca_crt);

  // Client Auth
  if (!client_crt.empty() && !client_key.empty()) {
    LoadCertificate(ctx.ssl_ctx, client_crt);
    LoadPrivateKey(ctx.ssl_ctx, client_key);
  }

  ctx.ssl = SSL_new(ctx.ssl_ctx);
  if (!ctx.ssl)
    throw std::runtime_error("openssl: cannot create ssl handle");

  if (!hostname.empty() && !SSL_set1_host(ctx.ssl, hostname.c_str()))
    throw std::runtime_error("openssl: cannot set hostname for verification");

  BIO* const bio = BIO_new(BioMethod());
  if (!bio)
    throw std::runtime_error("openssl: cannot create BIO");
  BIO_set_data(bio, &ctx);
  SSL_set_bio(ctx.ssl, bio, bio);

  if (sock_->Connect(sockfd, addr, addrlen) && errno != EINPROGRESS) {
    throw std::system_error(errno, std::generic_category());
  }

  pollfd pfd{ctx.fd, POLLOUT | POLLIN, 0};
  int re = -1;
  do {
    if (poll(&pfd, 1, -1) < 0)
      throw std::runtime_error("socket unavailable");

    ERR_clear_error();
    re = SSL_connect(ctx.ssl);
    if (re == 1)
      break;
    const int err = SSL_get_error(ctx.ssl, re);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      continue;
    }

    this->Shutdown(ctx.fd, SHUT_RDWR);
    CheckResult(ctx.ssl, re, ECONNREFUSED);
  } while (true);

  return 0;
}

ssize_t OpensslSocket::Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  auto& ctx = [&]() -> auto& {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.at(sockfd);
  }();
  const std::lock_guard lock(ctx.mtx);
  ERR_clear_error();
  return CheckResult(ctx.ssl, SSL_read(ctx.ssl, buf, static_cast<int>(len)));
}

ssize_t OpensslSocket::Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  auto& ctx = [&]() -> auto& {
    std::lock_guard<std::mutex> lock(mtx_);
    return contexts_.at(sockfd);
  }();
  const std::lock_guard lock(ctx.mtx);
  ERR_clear_error();
  return CheckResult(ctx.ssl, SSL_write(ctx.ssl, buf, static_cast<int>(len)));
}

int OpensslSocket::Accept4(int /*sockfd*/, sockaddr* /*addr*/, socklen_t* /*addrlen*/, int /*flags*/) {
  throw std::runtime_error("no crt provided");
}

int OpensslSocket::Accept(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags, const std::string& ca_crt,
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
  ctx.fd = connection_fd;

  ctx.ssl_ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx.ssl_ctx)
    throw std::runtime_error("openssl: cannot create server context");

  AddCaCerts(ctx.ssl_ctx, ca_crt);

  if (req_client_auth_ && client_auth)
    SSL_CTX_set_verify(ctx.ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);

  LoadCertificate(ctx.ssl_ctx, server_crt);
  LoadPrivateKey(ctx.ssl_ctx, server_key);

  ctx.ssl = SSL_new(ctx.ssl_ctx);
  if (!ctx.ssl)
    throw std::runtime_error("openssl: cannot create ssl handle");

  BIO* const bio = BIO_new(BioMethod());
  if (!bio)
    throw std::runtime_error("openssl: cannot create BIO");
  BIO_set_data(bio, &ctx);
  SSL_set_bio(ctx.ssl, bio, bio);

  pollfd pfd{ctx.fd, POLLOUT | POLLIN, 0};
  int re = -1;
  do {
    if (poll(&pfd, 1, -1) < 0)
      throw std::runtime_error("socket unavailable");

    ERR_clear_error();
    re = SSL_accept(ctx.ssl);
    if (re == 1)
      break;
    const int err = SSL_get_error(ctx.ssl, re);
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      continue;
    }

    try {
      CheckResult(ctx.ssl, re, ECONNABORTED);
    } catch (...) {
      this->Close(ctx.fd);
      throw;
    }
  } while (true);

  return ctx.fd;
}

#include "dispatcher.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <cassert>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

#include "mbedtls_socket.h"

using namespace edgeless::ttls;
using namespace std::string_literals;

bool Dispatcher::IsTls(int sockfd) {
  const std::lock_guard<std::mutex> lock(mtx_);
  return tls_fds_.find(sockfd) != tls_fds_.cend();
}

Dispatcher::Dispatcher(std::string_view config, const SocketPtr& raw, const MbedtlsSockPtr& tls)
    : raw_(raw), tls_(tls) {
  assert(raw);
  assert(tls);

  // parse config
  try {
    config_ = std::make_unique<nlohmann::json>(nlohmann::json::parse(config));
  } catch (const nlohmann::json::exception& e) {
    throw std::runtime_error("dispatcher: cannot parse config: "s + e.what());
  }
}

Dispatcher::~Dispatcher() = default;

int Dispatcher::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  // 1. parse IP out of sockaddr
  std::string ip_buf(NI_MAXHOST, ' ');
  std::string port_buf(NI_MAXSERV, ' ');

  int ret = getnameinfo(addr, addrlen, ip_buf.data(), NI_MAXHOST, port_buf.data(), NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
  if (ret != 0) {
    return -1;
  }

  ip_buf = ip_buf.substr(0, ip_buf.find('\0'));
  port_buf = port_buf.substr(0, port_buf.find('\0'));
  std::string ip_port = ip_buf + ":" + port_buf;

  // 2. check if not in json --> raw_->Connect(...)
  if (Conf()["tls"].find(ip_port) == Conf()["tls"].cend())
    return raw_->Connect(sockfd, addr, addrlen);

  // 3. else --> save fd + tls_->Connect(...)
  try {
    {
      std::lock_guard<std::mutex> lock(mtx_);
      tls_fds_.insert(sockfd);
    }
    return tls_->Connect(sockfd, addr, addrlen, Conf()["tls"][ip_port]);
  } catch (const std::runtime_error&) {
    return -1;
  }
}

ssize_t Dispatcher::Recv(int sockfd, void* buf, size_t len, int flags) {
  // when fd unknown -> raw->Recv()
  if (!IsTls(sockfd))
    return raw_->Recv(sockfd, buf, len, flags);

  try {
    return tls_->Recv(sockfd, buf, len, flags);
  } catch (const std::runtime_error&) {
    return -1;
  }
}

ssize_t Dispatcher::Send(int sockfd, const void* buf, size_t len, int flags) {
  if (!IsTls(sockfd))
    return raw_->Send(sockfd, buf, len, flags);

  try {
    return tls_->Send(sockfd, buf, len, flags);
  } catch (const std::runtime_error&) {
    return -1;
  }
}

int Dispatcher::Shutdown(int sockfd, int how) {
  if (!IsTls(sockfd))
    return raw_->Shutdown(sockfd, how);

  try {
    tls_->Shutdown(sockfd, how);
    return 0;
  } catch (const std::runtime_error&) {
    return -1;
  }
}

int Dispatcher::Close(int sockfd) {
  if (!IsTls(sockfd))
    return raw_->Close(sockfd);

  try {
    tls_->Close(sockfd);
    tls_fds_.erase(sockfd);
    return 0;
  } catch (const std::runtime_error&) {
    return -1;
  }
}

const nlohmann::json& Dispatcher::Conf() const noexcept {
  return *config_;
}

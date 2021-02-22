#include "dispatcher.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#include <cassert>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

using namespace edgeless::ttls;
using namespace std::string_literals;

Dispatcher::Dispatcher(std::string_view config, const SocketPtr& raw, const SocketPtr& tls)
    : raw_(raw), tls_(tls) {
  assert(raw);
  assert(tls);

  // parse config
  // { "tls": ["127.0.0.1:443", "192.168.0.1:2001"] }
  try {
    config_ = std::make_unique<nlohmann::json>(nlohmann::json::parse(config));

    std::vector<std::string> v = (*config_)["tls"];
    std::copy(v.begin(),
              v.end(),
              std::inserter(tls_addrs_, tls_addrs_.end()));

  } catch (const nlohmann::json::exception& e) {
    throw std::runtime_error("dispatcher: cannot parse config: "s + e.what());
  }
}

Dispatcher::~Dispatcher() = default;

int Dispatcher::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  // 1. parse IP out of sockaddr
  std::string ip_buf(addrlen, ' ');
  std::string port_buf(addrlen, ' ');
  getnameinfo(addr, addrlen, ip_buf.data(), addrlen, port_buf.data(), addrlen, 0);
  std::string ip_port = ip_buf + port_buf;

  // 2. check if in json --> save fd + tls_->Connect(...)
  if (tls_addrs_.find(ip_port) != tls_addrs_.end()) {
    try {
      tls_->Connect(sockfd, addr, addrlen);
      tls_fds_.insert(sockfd);
      return 0;
    } catch (const std::runtime_error&) {
      return -1;
    }
  } else {
    // 3. else --> raw_->Connect(...)
    return raw_->Connect(sockfd, addr, addrlen);
  }
}

ssize_t Dispatcher::Recv(int sockfd, void* buf, size_t len, int flags) {
  // when fd known -> tls_->Send()
  if (tls_fds_.find(sockfd) != tls_fds_.end()) {
    try {
      tls_->Recv(sockfd, buf, len, flags);
      tls_fds_.insert(sockfd);
      return 0;
    } catch (const std::runtime_error&) {
      return -1;
    }
  } else {
    return raw_->Recv(sockfd, buf, len, flags);
  }
}

ssize_t Dispatcher::Send(int sockfd, const void* buf, size_t len, int flags) {
  if (tls_fds_.find(sockfd) != tls_fds_.end()) {
    try {
      tls_->Send(sockfd, buf, len, flags);
      tls_fds_.insert(sockfd);
      return 0;
    } catch (const std::runtime_error&) {
      return -1;
    }
  } else {
    return raw_->Send(sockfd, buf, len, flags);
  }
}

const nlohmann::json& Dispatcher::Conf() const noexcept {
  return *config_;
}

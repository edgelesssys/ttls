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
  std::string ip_buf(NI_MAXHOST, ' ');
  std::string port_buf(NI_MAXSERV, ' ');

  int ret = getnameinfo(addr, addrlen, ip_buf.data(), NI_MAXHOST, port_buf.data(), NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
  if (ret != 0) {
    return -1;
  }

  ip_buf = ip_buf.substr(0, ip_buf.find('\0'));
  port_buf = port_buf.substr(0, port_buf.find('\0'));
  std::string ip_port = ip_buf + ":" + port_buf;

  // 2. check if in json --> save fd + tls_->Connect(...)
  if (tls_addrs_.find(ip_port) != tls_addrs_.end()) {
    try {
      tls_fds_.insert(sockfd);
      return tls_->Connect(sockfd, addr, addrlen);
    } catch (const std::runtime_error&) {
      return -1;
    }
  } else {
    // 3. else --> raw_->Connect(...)
    return raw_->Connect(sockfd, addr, addrlen);
  }
}

ssize_t Dispatcher::Recv(int sockfd, void* buf, size_t len, int flags) {
  // when fd known -> tls_->Recv()
  if (tls_fds_.find(sockfd) != tls_fds_.end()) {
    try {
      tls_fds_.insert(sockfd);
      return tls_->Recv(sockfd, buf, len, flags);
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
      tls_fds_.insert(sockfd);
      return tls_->Send(sockfd, buf, len, flags);
    } catch (const std::runtime_error&) {
      return -1;
    }
  } else {
    return raw_->Send(sockfd, buf, len, flags);
  }
}

int Dispatcher::Close(int sockfd) {
  if (tls_fds_.find(sockfd) != tls_fds_.end()) {
    try {
      tls_->Close(sockfd);
      tls_fds_.erase(sockfd);
      return 0;
    } catch (const std::runtime_error&) {
      return -1;
    }
  } else {
    return raw_->Close(sockfd);
  }
}

const nlohmann::json& Dispatcher::Conf() const noexcept {
  return *config_;
}

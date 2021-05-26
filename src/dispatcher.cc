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
  const std::lock_guard<std::mutex> lock(tls_fds_mtx_);
  return tls_fds_.find(sockfd) != tls_fds_.cend();
}

Dispatcher::Dispatcher(std::string_view config, RawSockPtr raw, MbedtlsSockPtr tls)
    : raw_(std::move(raw)), tls_(std::move(tls)) {
  assert(raw_);
  assert(tls_);

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

  ip_buf.erase(ip_buf.find('\0'));
  port_buf.erase(port_buf.find('\0'));
  std::string domain_port = ip_buf + ":" + port_buf;
  std::string hostname;
  // prefer domains over IPs
  {
    const std::lock_guard<std::mutex> lock(ip_domain_mtx_);
    const auto it = ip_domain_.find(ip_buf);
    if (it != ip_domain_.cend()) {
      hostname = it->second;
      domain_port = hostname + ":" + port_buf;
    }
  }

  // 2. check if not in json --> raw_->Connect(...)
  const auto& entries = Conf()["tls"]["Outgoing"];
  if (entries.find(domain_port) == entries.cend())
    return raw_->Connect(sockfd, addr, addrlen);

  // 3. else --> save fd + tls_->Connect(...)
  try {
    {
      std::lock_guard<std::mutex> lock(tls_fds_mtx_);
      tls_fds_.insert(sockfd);
    }
    const auto& entry = entries[domain_port];
    return tls_->Connect(sockfd, addr, addrlen, hostname, entry["cacrt"],
                         entry["clicrt"], entry["clikey"]);
  } catch (const std::system_error& e) {
    errno = e.code().value();
    return -1;
  }
}

int Dispatcher::Bind(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  // bind(3, {sa_family=AF_INET6, sin6_port=htons(9000), inet_pton(AF_INET6, "::", &sin6_addr), sin6_flowinfo=htonl(0), sin6_scope_id=0}, 28)
  // TODO: Check if IP is recoverable at all

  // 1. parse IP out of sockaddr
  std::string port_buf(NI_MAXSERV, ' ');
  int ret = getnameinfo(addr, addrlen, nullptr, 0, port_buf.data(), NI_MAXSERV, NI_NUMERICSERV);
  if (ret != 0) {
    return -1;
  }
  port_buf.erase(port_buf.find('\0'));

  // 2. check if in json --> raw_->Connect(...)
  const auto& entries = Conf()["tls"]["Incoming"];
  if (entries.find("*:" + port_buf) != entries.cend()) {
    std::lock_guard<std::mutex> lock(fd_entry_mtx_);
    fd_entry_.emplace(sockfd, "*:" + port_buf);
  }
  return raw_->Bind(sockfd, addr, addrlen);
}

ssize_t Dispatcher::Recv(int sockfd, void* buf, size_t len, int flags) {
  // when fd unknown -> raw->Recv()
  if (!IsTls(sockfd))
    return raw_->Recv(sockfd, buf, len, flags);

  try {
    return tls_->Recv(sockfd, buf, len, flags);
  } catch (const std::system_error& e) {
    errno = e.code().value();
    return -1;
  }
}

ssize_t Dispatcher::Send(int sockfd, const void* buf, size_t len, int flags) {
  if (!IsTls(sockfd))
    return raw_->Send(sockfd, buf, len, flags);

  try {
    return tls_->Send(sockfd, buf, len, flags);
  } catch (const std::system_error& e) {
    errno = e.code().value();
    return -1;
  }
}

int Dispatcher::Shutdown(int sockfd, int how) {
  if (!IsTls(sockfd))
    return raw_->Shutdown(sockfd, how);

  try {
    tls_->Shutdown(sockfd, how);
    return 0;
  } catch (const std::system_error& e) {
    errno = e.code().value();
    return -1;
  }
}

int Dispatcher::Close(int sockfd) {
  if (!IsTls(sockfd))
    return raw_->Close(sockfd);

  try {
    tls_->Close(sockfd);
    {
      std::lock_guard<std::mutex> lock(tls_fds_mtx_);
      tls_fds_.erase(sockfd);
    }
    return 0;
  } catch (const std::system_error& e) {
    errno = e.code().value();
    return -1;
  }
}

int Dispatcher::Getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** res) {
  // TODO: Check if service/port is ever used
  // [pid 108970] client->getaddrinfo("google.de", nil, 0xc00009c090, 0xc0000a4010)                       = 0

  int ret = raw_->Getaddrinfo(node, service, hints, res);
  if (ret != 0 || !node) {
    return ret;
  }

  for (const auto& el : Conf()["tls"]["Outgoing"].items()) {
    const std::string domain = el.key().substr(0, el.key().find(':'));

    if (node == domain) {
      // get all IPs

      // save all (IPs, domain) in ip_domain_
      for (const addrinfo* rp = *res; rp != nullptr; rp = rp->ai_next) {
        //parse ip out of sockaddr
        std::string ip_buf(NI_MAXHOST, ' ');
        ret = getnameinfo(rp->ai_addr, rp->ai_addrlen, ip_buf.data(), NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
        if (ret != 0) {
          return -1;
        }
        ip_buf.erase(ip_buf.find('\0'));
        {
          const std::lock_guard<std::mutex> lock(ip_domain_mtx_);
          ip_domain_.try_emplace(std::move(ip_buf), domain);
        }
      }
      return 0;
    }
  }
  return 0;
}

int Dispatcher::Accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) {
  const auto entry = [&] {
    std::lock_guard<std::mutex> lock(fd_entry_mtx_);
    return fd_entry_.find(sockfd);
  }();

  if (entry == fd_entry_.cend()) {
    return raw_->Accept4(sockfd, addr, addrlen, flags);
  }
  const auto entry_name = entry->second;

  try {
    const auto& conf = Conf()["tls"]["Incoming"][entry_name];
    const int client_fd = tls_->Accept(sockfd, addr, addrlen, flags, conf["cacrt"],
                                       conf["clicrt"], conf["clikey"], conf["clientAuth"]);
    {
      std::lock_guard<std::mutex> lock(tls_fds_mtx_);
      tls_fds_.insert(client_fd);
    }
    return client_fd;
  } catch (const std::system_error& e) {
    errno = e.code().value();
    return -1;
  }
}

const nlohmann::json& Dispatcher::Conf() const noexcept {
  return *config_;
}

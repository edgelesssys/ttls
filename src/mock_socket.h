#pragma once

#include <ttls/mbedtls_socket.h>

#include <algorithm>
#include <array>
#include <string>
#include <unordered_map>
#include <vector>

#include "util.h"

namespace edgeless::ttls {

struct Connection {
  const sockaddr* addr{};
  socklen_t addrlen{};
  std::string ca_crt{};
  std::vector<char> msg_buf{};
};

struct MockSocket : MbedtlsSocket, RawSocket {
  std::unordered_map<int, Connection> connections;

  int Close(int fd) override {
    if (connections.erase(fd) != 1)
      return -1;
    return 0;
  }

  int Shutdown(int /*fd*/, int /*how*/) override {
    return 0;
  }

  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override {
    if (!connections.try_emplace(sockfd, Connection{addr, addrlen}).second)
      return -1;
    return 0;
  }

  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen, const std::string& ca_crt) override {
    if (!connections.try_emplace(sockfd, Connection{addr, addrlen, ca_crt}).second)
      return -1;
    return 0;
  }

  ssize_t Recv(int sockfd, void* buf, size_t len, int /*flags*/) override {
    auto& v = connections.at(sockfd).msg_buf;
    const std::string prefix("OK-");
    const size_t ret = std::min(v.size() + prefix.size(), len);

    std::string resp = prefix;
    resp.append(v.cbegin(), v.cend());
    memcpy(buf, resp.data(), ret);
    v.erase(v.begin(), v.begin() + ret - prefix.size());
    return ret;
  }

  ssize_t Send(int sockfd, const void* buf, size_t len, int /*flags*/) override {
    auto& v = connections.at(sockfd).msg_buf;
    const auto p = static_cast<const char*>(buf);
    v.insert(v.end(), p, p + len);
    return len;
  }

  sockaddr getaddrinfo_addr{};
  addrinfo getaddrinfo_addrinfo{};

  int Getaddrinfo(const char* node, const char* /*service*/, const addrinfo* /*hints*/, addrinfo** res) override {
    if (std::string_view(node) == "service.name") {
      getaddrinfo_addr = MakeSockaddr("133.133.133.133", 0);
    } else if (std::string_view(node) == "other.service.name") {
      getaddrinfo_addr = MakeSockaddr("200.200.200.200", 0);
    } else {
      return -1;
    }
    getaddrinfo_addrinfo = {};
    getaddrinfo_addrinfo.ai_addr = &getaddrinfo_addr;
    getaddrinfo_addrinfo.ai_addrlen = sizeof(getaddrinfo_addr);
    *res = &getaddrinfo_addrinfo;
    return 0;
  }
};

}  // namespace edgeless::ttls

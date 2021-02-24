#pragma once

#include <ttls/socket.h>

#include <vector>

namespace edgeless::ttls {

struct MockSocket : Socket {
  std::map<int, std::pair<const sockaddr*, socklen_t>> connect;
  std::map<int, std::vector<char>> msg_buf;
  int connect_ret = -1;

  int Close(int fd) override {
    if (connect.erase(fd) != 1)
      return -1;
    msg_buf.erase(fd);
    return 0;
  }

  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override {
    connect.emplace(sockfd, std::make_pair(addr, addrlen));
    return connect_ret;
  }

  ssize_t Recv(int sockfd, void* buf, size_t len, int /*flags*/) override {
    auto& v = msg_buf[sockfd];
    const std::string prefix("OK-");
    size_t ret = v.size() + prefix.size() < len ? v.size() + prefix.size() : len;

    std::string resp(v.begin(), v.end());
    resp = prefix + resp;
    memcpy(buf, resp.data(), ret);
    v.erase(v.begin(), v.begin() + ret - prefix.size());
    return ret;
  }

  ssize_t Send(int sockfd, const void* buf, size_t len, int /*flags*/) override {
    auto& v = msg_buf[sockfd];
    std::copy(reinterpret_cast<const char*>(buf), reinterpret_cast<const char*>(buf) + len, back_inserter(v));
    return len;
  }
};

}  // namespace edgeless::ttls

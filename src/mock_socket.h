#pragma once

#include <ttls/socket.h>

#include <tuple>
#include <vector>

namespace edgeless::ttls {

struct MockSocket : Socket {
  int Close(int /*fd*/) override {
    return -1;
  }

  std::vector<std::tuple<int, const sockaddr*, socklen_t>> connect;
  int connect_ret = -1;

  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override {
    connect.emplace_back(sockfd, addr, addrlen);
    return connect_ret;
  }

  ssize_t Recv(int /*sockfd*/, void* /*buf*/, size_t /*len*/, int /*flags*/) override {
    return -1;
  }

  ssize_t Send(int /*sockfd*/, const void* /*buf*/, size_t /*len*/, int /*flags*/) override {
    return -1;
  }
};

}  // namespace edgeless::ttls

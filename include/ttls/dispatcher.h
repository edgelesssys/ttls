#pragma once

#include <memory>
#include <nlohmann/json_fwd.hpp>
#include <string_view>

#include "socket.h"

namespace edgeless::ttls {

class Dispatcher final {
 public:
  /**
   * Create a dispatcher object.
   *
   * @param config Configuration string as JSON.
   * @param raw Socket functions that will be used if connection should not be wrapped.
   * @param tls Socket functions that will be used if connection should be wrapped.
   */
  Dispatcher(std::string_view config, const SocketPtr& raw, const SocketPtr& tls);

  ~Dispatcher();

  // socket functions
  int Close(int fd);
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen);
  ssize_t Recv(int sockfd, void* buf, size_t len, int flags);
  ssize_t Send(int sockfd, const void* buf, size_t len, int flags);

 private:
  const nlohmann::json& Conf() const noexcept;

  std::unique_ptr<nlohmann::json> config_;
  SocketPtr raw_;
  SocketPtr tls_;
};

}  // namespace edgeless::ttls

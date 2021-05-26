#pragma once

#include <netdb.h>

#include <memory>
#include <mutex>
#include <nlohmann/json_fwd.hpp>
#include <string_view>
#include <unordered_set>

#include "mbedtls_socket.h"
#include "raw_socket.h"
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
  Dispatcher(std::string_view config, RawSockPtr raw, MbedtlsSockPtr tls);

  ~Dispatcher();

  // socket functions
  int Close(int fd);
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen);
  int Bind(int sockfd, const sockaddr* addr, socklen_t addrlen);
  int Accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags);
  ssize_t Recv(int sockfd, void* buf, size_t len, int flags);
  ssize_t Send(int sockfd, const void* buf, size_t len, int flags);
  int Shutdown(int sockfd, int how);
  int Getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** res);

 private:
  const nlohmann::json& Conf() const noexcept;
  bool IsTls(int sockfd);

  //TODO: Refacor to combine mtx and data structure

  std::mutex tls_fds_mtx_;
  std::mutex ip_domain_mtx_;
  std::mutex fd_entry_mtx_;

  std::unordered_map<std::string, std::string> ip_domain_;
  // contains connected and accepted sockfds
  std::unordered_set<int> tls_fds_;
  // map bound fds to their entryname in the json
  std::unordered_map<int, std::string> fd_entry_;
  std::unique_ptr<nlohmann::json> config_;
  RawSockPtr raw_;
  MbedtlsSockPtr tls_;
};

}  // namespace edgeless::ttls

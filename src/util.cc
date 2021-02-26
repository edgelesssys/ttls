#include "util.h"

namespace edgeless::ttls {
sockaddr MakeSockaddr(std::string_view ip, uint16_t port) {
  sockaddr_in sock_addr{};
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_port = htons(port);
  inet_aton(ip.data(), &sock_addr.sin_addr);
  return reinterpret_cast<sockaddr&>(sock_addr);
}
}  // namespace edgeless::ttls

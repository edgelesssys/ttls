#pragma once

#include <arpa/inet.h>

#include <string_view>

namespace edgeless::ttls {

sockaddr MakeSockaddr(std::string_view ip, uint16_t port);

}  // namespace edgeless::ttls

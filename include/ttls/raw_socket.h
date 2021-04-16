#pragma once

#include <netdb.h>

#include "socket.h"

namespace edgeless::ttls {

class RawSocket : public Socket {
 public:
  virtual int Getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** res) = 0;
};

typedef std::shared_ptr<RawSocket> RawSockPtr;

}  // namespace edgeless::ttls

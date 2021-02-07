#include "mbedtls_socket.h"

#include <mbedtls/ssl.h>

using namespace edgeless::ttls;

int MbedtlsSocket::Close(int /*fd*/) {
  return -1;
}

int MbedtlsSocket::Connect(int /*sockfd*/, const sockaddr* /*addr*/, socklen_t /*addrlen*/) {
  return -1;
}

ssize_t MbedtlsSocket::Recv(int /*sockfd*/, void* /*buf*/, size_t /*len*/, int /*flags*/) {
  return -1;
}

ssize_t MbedtlsSocket::Send(int /*sockfd*/, const void* /*buf*/, size_t /*len*/, int /*flags*/) {
  return -1;
}

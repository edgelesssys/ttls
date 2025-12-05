#pragma once

#ifdef TTLS_OPENSSL

#include <ttls/openssl_socket.h>
namespace edgeless::ttls {
using TlsSocket = OpensslSocket;
using TlsSockPtr = OpensslSockPtr;
}  // namespace edgeless::ttls
#define MBEDTLS_SSL_VERIFY_NONE 0      // NOLINT
#define MBEDTLS_SSL_VERIFY_REQUIRED 2  // NOLINT
#define MBEDTLS_NET_LISTEN_BACKLOG 10  // NOLINT

#else

#include <ttls/mbedtls_socket.h>
namespace edgeless::ttls {
using TlsSocket = MbedtlsSocket;
using TlsSockPtr = MbedtlsSockPtr;
}  // namespace edgeless::ttls

#endif

#pragma once

#include <string>

#include "mbedtls/certs.h"
#include "mbedtls/config.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/platform.h"
#include "mbedtls/ssl.h"

namespace edgeless::ttls {

class MbedtlsContext final {
 public:
  mbedtls_net_context server_fd;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt cacert;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_context entropy;

  MbedtlsContext();
  ~MbedtlsContext();

 private:
  std::string static readCert(const char* filename);
};
}  // namespace edgeless::ttls

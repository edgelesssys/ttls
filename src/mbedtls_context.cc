
#include "mbedtls_context.h"

#include <fstream>
#include <sstream>

using namespace edgeless::ttls;

MbedtlsContext::MbedtlsContext() : server_fd{}, ssl{}, conf{}, cacert{}, ctr_drbg{}, entropy{} {
  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                        nullptr,
                        0);

  std::string cert = readCert("cert.pem");
  mbedtls_x509_crt_parse(&cacert, (const unsigned char*)cert.c_str(),
                         cert.size());
}

MbedtlsContext::~MbedtlsContext() {
  mbedtls_net_free(&server_fd);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

std::string MbedtlsContext::readCert(const char* filename) {
  std::ifstream infile(filename);
  auto cert = std::ostringstream{};
  if (infile) {
    cert << infile.rdbuf();
    infile.close();
    return (cert.str());
  }
  return "";
}

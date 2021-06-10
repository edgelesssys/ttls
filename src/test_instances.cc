#include "test_instances.h"

#include <condition_variable>
#include <ctime>
#include <iomanip>
#include <mutex>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"

using namespace edgeless;

extern "C" int edgeless_ttls_test_server(void notify(void*), void* event, const char* srv_crt, const char* cas_pem, const char* srv_key, const char* port, int client_auth);
extern "C" int edgeless_ttls_test_client(const char* srv_crt, const char* cas_pem, const char* srv_key, const char* port, bool client_auth);

namespace {
struct Event {
  std::mutex m;
  std::condition_variable cv;
  bool ready;
};
}  // namespace

static void Notify(void* event) {
  auto& ev = *static_cast<Event*>(event);

  const std::lock_guard lock(ev.m);
  ev.ready = true;
  ev.cv.notify_one();
}

std::thread ttls::StartTestServer(const std::string& port, int client_auth, const std::string& ca_crt, const std::string& server_crt, const std::string& server_key) {
  Event ev{};
  std::thread t1([=, &ev] {
    edgeless_ttls_test_server(Notify, &ev, server_crt.c_str(), ca_crt.c_str(), server_key.c_str(), port.c_str(), client_auth);
  });
  {
    std::unique_lock<std::mutex> lk(ev.m);
    ev.cv.wait(lk, [&] { return ev.ready; });
  }
  return t1;
}

std::thread ttls::StartTestClient(const std::string& port, bool client_auth, const std::string& ca_crt, const std::string& cli_crt, const std::string& cli_key) {
  return std::thread([=] {
    edgeless_ttls_test_client(cli_crt.c_str(), ca_crt.c_str(), cli_key.c_str(), port.c_str(), client_auth);
  });
}

static void CheckResult(const int ret) {
  if (ret < 0) {
    using namespace std::string_literals;
    std::array<char, 100> buf{};
    mbedtls_strerror(ret, buf.data(), buf.size());
    printf("mbedtls: -0x%04x: %s", static_cast<unsigned int>(-ret), buf.data());
    throw std::system_error(EPROTO, std::generic_category(), "mbedtls: "s + buf.data());
  }
}

static std::string GenerateCertificateReq(mbedtls_ctr_drbg_context& ctr_drbg, const std::string& key_pem) {
  mbedtls_x509write_csr req;
  mbedtls_pk_context key;

  mbedtls_x509write_csr_init(&req);
  mbedtls_pk_init(&key);

  mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
  CheckResult(mbedtls_x509write_csr_set_subject_name(&req, "CN=localhost,O=Test Org,C=UK"));

  CheckResult(mbedtls_pk_parse_key(&key, reinterpret_cast<const unsigned char*>(key_pem.data()), key_pem.size() + 1, nullptr, 0));
  mbedtls_x509write_csr_set_key(&req, &key);

  std::string csr_pem(4096, ' ');
  CheckResult(mbedtls_x509write_csr_pem(&req, reinterpret_cast<unsigned char*>(csr_pem.data()), csr_pem.size(), mbedtls_ctr_drbg_random, &ctr_drbg));
  csr_pem.erase(csr_pem.find('\0'));

  mbedtls_x509write_csr_free(&req);
  mbedtls_pk_free(&key);
  return csr_pem;
}

static std::string GenerateCertificate(mbedtls_ctr_drbg_context& ctr_drbg, const std::string& issuer_key, const std::string& csr_pem, const std::string& serial_number, const bool self_sign) {
  const std::string issuer_name("CN=CA,O=Test Org,C=UK");
  std::string subject_name(256, ' ');

  mbedtls_mpi serial;
  mbedtls_pk_context loaded_issuer_key;
  mbedtls_pk_context loaded_subject_key;
  mbedtls_pk_context* issuer_key_ptr = &loaded_issuer_key;
  mbedtls_pk_context* subject_key_ptr = &loaded_subject_key;
  mbedtls_x509write_cert crt;
  mbedtls_x509_csr csr;
  mbedtls_x509_crt issuer_crt;

  mbedtls_mpi_init(&serial);
  mbedtls_x509write_crt_init(&crt);
  mbedtls_x509_csr_init(&csr);
  mbedtls_x509_crt_init(&issuer_crt);
  mbedtls_pk_init(&loaded_issuer_key);
  mbedtls_pk_init(&loaded_subject_key);

  CheckResult(mbedtls_mpi_read_string(&serial, 10, serial_number.data()));

  if (!self_sign) {
    CheckResult(mbedtls_x509_csr_parse(&csr, reinterpret_cast<const unsigned char*>(csr_pem.data()), csr_pem.size() + 1));
    CheckResult(mbedtls_x509_dn_gets(subject_name.data(), subject_name.size(), &csr.subject));
    subject_name.erase(subject_name.find('\0'));

    subject_key_ptr = &csr.pk;
  }
  CheckResult(mbedtls_pk_parse_key(&loaded_issuer_key, reinterpret_cast<const unsigned char*>(issuer_key.data()), issuer_key.size() + 1, nullptr, 0));

  if (self_sign) {
    subject_key_ptr = issuer_key_ptr;
    subject_name = issuer_name;
  }
  mbedtls_x509write_crt_set_subject_key(&crt, subject_key_ptr);
  mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key_ptr);

  CheckResult(mbedtls_x509write_crt_set_subject_name(&crt, subject_name.data()));
  CheckResult(mbedtls_x509write_crt_set_issuer_name(&crt, issuer_name.data()));

  mbedtls_x509write_crt_set_version(&crt, 2);
  mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
  CheckResult(mbedtls_x509write_crt_set_serial(&crt, &serial));

  auto t = std::time(nullptr);
  auto tm = *std::gmtime(&t);
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y%m%d000000");
  auto not_before = oss.str();

  tm.tm_mday += 1;
  tm.tm_isdst = -1;
  auto next_day = mktime(&tm);
  tm = *std::gmtime(&next_day);
  oss.str("");
  oss << std::put_time(&tm, "%Y%m%d235959");
  auto not_after = oss.str();

  CheckResult(mbedtls_x509write_crt_set_validity(&crt, not_before.data(), not_after.data()));

  CheckResult(mbedtls_x509write_crt_set_basic_constraints(&crt, self_sign,
                                                          -1));
  CheckResult(mbedtls_x509write_crt_set_subject_key_identifier(&crt));
  CheckResult(mbedtls_x509write_crt_set_authority_key_identifier(&crt));

  std::string crt_pem(4096, ' ');
  CheckResult(mbedtls_x509write_crt_pem(&crt, reinterpret_cast<unsigned char*>(crt_pem.data()), crt_pem.size(),
                                        mbedtls_ctr_drbg_random, &ctr_drbg));
  crt_pem.erase(crt_pem.find('\0'));

  mbedtls_mpi_free(&serial);
  mbedtls_x509write_crt_free(&crt);
  mbedtls_x509_csr_free(&csr);
  mbedtls_x509_crt_free(&issuer_crt);
  mbedtls_pk_free(&loaded_issuer_key);
  mbedtls_pk_free(&loaded_subject_key);

  return crt_pem;
}

static std::string GenerateKey(mbedtls_ctr_drbg_context& ctr_drbg) {
  const int keysize = 2048;

  mbedtls_pk_context key;

  mbedtls_pk_init(&key);

  CheckResult(mbedtls_pk_setup(&key,
                               mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)));

  CheckResult(mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg,
                                  keysize, 65537));

  std::string pKey(16000, ' ');
  CheckResult(mbedtls_pk_write_key_pem(&key, reinterpret_cast<unsigned char*>(pKey.data()), pKey.size()));
  pKey.erase(pKey.find('\0'));

  mbedtls_pk_free(&key);

  return pKey;
}

std::string ttls::JSONescape(const std::string& s) {
  std::string encoded = s;
  size_t pos = 0;
  while ((pos = encoded.find('\n', pos)) != std::string::npos) {
    encoded.replace(pos, 1, "\\r\\n");
    pos += 4;
  }
  return encoded;
}

ttls::TestCredentials::TestCredentials() {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  const std::string pers = "pers";

  CheckResult(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    reinterpret_cast<const unsigned char*>(pers.data()),
                                    pers.size()));

  const std::string ca_key = GenerateKey(ctr_drbg);
  ca_crt = GenerateCertificate(ctr_drbg, ca_key, "", "1", true);

  server_key = GenerateKey(ctr_drbg);
  const std::string server_csr = GenerateCertificateReq(ctr_drbg, server_key);
  server_crt = GenerateCertificate(ctr_drbg, ca_key, server_csr, "2", false);

  cli_key = GenerateKey(ctr_drbg);
  const std::string cli_csr = GenerateCertificateReq(ctr_drbg, cli_key);
  cli_crt = GenerateCertificate(ctr_drbg, ca_key, cli_csr, "3", false);

  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
}

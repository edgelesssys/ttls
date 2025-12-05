#include <plthook/plthook.h>
#include <sys/syscall.h>
#include <ttls/ttls.h>
#include <unistd.h>

#include <cstdarg>
#include <memory>

extern "C" {
void invokemain();
}

static long (*syscall_func)(long int __sysno, ...);

class Sock final : public edgeless::ttls::RawSocket {
 public:
  int Connect(int /*sockfd*/, const sockaddr* /*addr*/, socklen_t /*addrlen*/) override {
    return -1;
  }
  int Bind(int sockfd, const sockaddr* addr, socklen_t addrlen) override {
    return bind(sockfd, addr, addrlen);
  }
  int Accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) override {
    return accept4(sockfd, addr, addrlen, flags);
  }
  ssize_t Send(int sockfd, const void* buf, size_t len, int /*flags*/)
      override {
    return write(sockfd, buf, len);
  }
  ssize_t Recv(int sockfd, void* buf, size_t len, int /*flags*/) override {
    return read(sockfd, buf, len);
  }
  int Shutdown(int fd, int how) override {
    return shutdown(fd, how);
  }
  int Close(int fd) override {
    return close(fd);
  }
  int Getaddrinfo(const char* /*node*/, const char* /*service*/, const addrinfo* /*hints*/, addrinfo** /*res*/) override {
    return -1;
  }
};

const std::string kCACrt =
    "-----BEGIN CERTIFICATE-----\\r\\n"
    "MIIFqzCCA5OgAwIBAgIUHcmS9icsDdUATku8BQjnvbVYo2YwDQYJKoZIhvcNAQEL\\r\\n"
    "BQAwWjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5\\r\\n"
    "MQwwCgYDVQQKDANPcmcxDDAKBgNVBAsMA09yZzEQMA4GA1UEAwwHVGVzdCBDQTAe\\r\\n"
    "Fw0yNTEyMDExNDU3MTJaFw0zNTExMjkxNDU3MTJaMFoxCzAJBgNVBAYTAlVTMQ4w\\r\\n"
    "DAYDVQQIDAVTdGF0ZTENMAsGA1UEBwwEQ2l0eTEMMAoGA1UECgwDT3JnMQwwCgYD\\r\\n"
    "VQQLDANPcmcxEDAOBgNVBAMMB1Rlc3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4IC\\r\\n"
    "DwAwggIKAoICAQCr4s6EJ1xK/xlcqzol75HLf0icAK6xUFS+7dAFuBMqezlD8o2+\\r\\n"
    "ycmo9K4FeuX7zQwJqn1QD6Eux12yLIXAXL/h7IDsfgxnVSerbnalNGJN7AlUX3Uw\\r\\n"
    "xJDiDihPuffamX0qd+y6tfa38KiTvppYC2Boz8nNHNtUhtO/WUMsdx3xQdSDLlyn\\r\\n"
    "/hwCuAB80HzNFzIEc6OdOV7fl5bhlX3T9onrCKmggbEHYp+Q/5CmBkT5PJGxtJ4W\\r\\n"
    "q08YgcjdNWIDDSpS7mD7nRcrm9mEwDdI82cjiSWVU2XXIS5n9XbWyoJNs3tzp+AU\\r\\n"
    "Ibq1iOyI8xa8y2BTgsd0uPxIXYHSkv+3F/TxFg3qmISRG3UPM3TDoLzEsazdRkI+\\r\\n"
    "xLVDLLRIXuAj+r/XT0U1gzYEYXmOYcnP0UJanOhgcDB+n3FONJ61+bW2EzswhtAr\\r\\n"
    "wHXzTsD7QWFPgDyqc6QU/KZx/5tcFK5GbsRrdOtVcLuqZSiSbGETXdwyrNfJh1lg\\r\\n"
    "LbZi8o6lXgsP3CCD+fnnQxgx6j0BPFUUayl1hQqLWe8RH9BzdO/wwKtuKI1N7i8O\\r\\n"
    "PI4Teoy8K/bT8y8pLk+oKBaZhADCm7TEtUEfzYTXSk+niXMAksv5vG4hmDIWkfZa\\r\\n"
    "gkN0nuXaSVWpeP7+/oaa11ueG4d+AFDq7FWinbNyrXqH6S80Ohj9Q4cgIwIDAQAB\\r\\n"
    "o2kwZzAdBgNVHQ4EFgQU5TWDJFE5K3YB+YEUD3iwIQDKzGAwHwYDVR0jBBgwFoAU\\r\\n"
    "5TWDJFE5K3YB+YEUD3iwIQDKzGAwDwYDVR0TAQH/BAUwAwEB/zAUBgNVHREEDTAL\\r\\n"
    "gglsb2NhbGhvc3QwDQYJKoZIhvcNAQELBQADggIBAEUh5vUkRLWX9MANCBPQkmlz\\r\\n"
    "EQNYVQkRgPU8Np4K0s3R6v5TTvqc0NLVX0boLiISsx844V5suA4j6qSt6TQ6ZD1+\\r\\n"
    "9krR8BgAdOwuuJpquVnu7QQpCFVzL7IdXxbTr2PTyhbDJW5FoEEkTZVc5D0r3QQT\\r\\n"
    "ponXEXrJqlxYB8XLa0VYOpz4BsWmj306jEyc3zM6mqlIDz+mWncqawjQZ5ZWP49k\\r\\n"
    "deaeNGw2f2gfwhdGQCfUuh60iCaGqldqzXBuk0khaMn8Kvkmhp19xrjlunbO+dYn\\r\\n"
    "3lTDPTfwnapvTDJMIaJMYtiWzQ39Eyuf2pCqxnMbX0tKEBPaphMYU3WeeH4tSs5K\\r\\n"
    "otVafcXintFit7AhiIGKeEf2aeUPu+lFBuqR9E0Z/dwkovWq5AWcC8yqtwGWeW+j\\r\\n"
    "Ap8HLM6iayyVyecFGq40CYLQrNFv/YjUpFlB8WinSGK/CXDSzUrfguu6IBHQav6L\\r\\n"
    "6lbAsrWGkMTfrA13kB3uD1VWz2/lscuhhoqSm/4FtNtv+8xq5LMPVHoDKiZJu5Sf\\r\\n"
    "W7xZulAnbdr0hf8sRjE3ngwB1sg8UyOHTN6JnR5CU6V7hfx6zoBAHkFNTWaI4Ul/\\r\\n"
    "CEcg1FB5IbvyfHJopZLIKTAOLvECJFVe3b8pLnRrkTJfLa2DmpYZ7MgfljuzejVL\\r\\n"
    "CSW0dhv10kU2+o+G8zv2\\r\\n"
    "-----END CERTIFICATE-----\\r\\n";

const std::string kServerCert =
    "-----BEGIN CERTIFICATE-----\\r\\n"
    "MIIFnDCCA4SgAwIBAgIUFkx3nShWY/JMPC5VsAkFoF9KiHQwDQYJKoZIhvcNAQEL\\r\\n"
    "BQAwWjELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5\\r\\n"
    "MQwwCgYDVQQKDANPcmcxDDAKBgNVBAsMA09yZzEQMA4GA1UEAwwHVGVzdCBDQTAe\\r\\n"
    "Fw0yNTEyMDExNDU3MTNaFw0zNTExMjkxNDU3MTNaMFwxCzAJBgNVBAYTAlVTMQ4w\\r\\n"
    "DAYDVQQIDAVTdGF0ZTENMAsGA1UEBwwEQ2l0eTEMMAoGA1UECgwDT3JnMQwwCgYD\\r\\n"
    "VQQLDANPcmcxEjAQBgNVBAMMCWxvY2FsaG9zdDCCAiIwDQYJKoZIhvcNAQEBBQAD\\r\\n"
    "ggIPADCCAgoCggIBAMvkB7VqSO/7G2qZcupVuvgY8yM7nT4AVoUzCtoHHFoa8/4B\\r\\n"
    "UHIC4CsBVYqlvQNs8DcKHHAmLcBUhgV2gh2qgAAsqtMqhFZxCFdaLeDw6YmbJQPR\\r\\n"
    "U/joQqxST2HhCJ9a4ld+Lywn8HDJMwkcEvfTN4m43MgU9mZ/0Sjk+pUZHj0iRNaf\\r\\n"
    "bx0WlVilYxFfnSr0uwI8/5KWhra2J/PusBh3ykuStKlVgUyQwpjeNOootyRpM7Ry\\r\\n"
    "QLlWQ+GtCqLA+JgLXRw0CPjuMIkgYe7CMTVF9dl8X6IZYm4pnaVFxvV5/KffOJ70\\r\\n"
    "FqKUxyOpQJhwh10d3awFj39TU/lpIKcjxlmCvm0wRS0pIkj+Bm/RoR1ikCaxXOYd\\r\\n"
    "X4lGYS5mhax+ucU44sBlFmhj144qwz7MskCYPQdt0gEv0y9TDs5BD9gD06oHGkXh\\r\\n"
    "Zr3t/W6MnYU1vfk91WcH6aZrEymUV8cepnPGHH9sNsR10gY2ynPG2+5bxL6lu45M\\r\\n"
    "kVCBGYNvisfYzVsvS/NHhj/NU5LRQThbCfzTZ/liB1Fz7KRtMMtnyjpkbRh7HETZ\\r\\n"
    "8yrYzCPBSBge74tXzRhKb2KjreZHcw4FXiLrrS6up7tEafwrGnNik/sNis6iuqPb\\r\\n"
    "83qLheJBEAyZlPx2sVRVJ0ghdIml07qLiLVrVtj5rxx5eoGfRqwzI4KUkl3HAgMB\\r\\n"
    "AAGjWDBWMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDAdBgNVHQ4EFgQUgTkcYTPZCUHP\\r\\n"
    "tf7lv3zsyv2jRDAwHwYDVR0jBBgwFoAU5TWDJFE5K3YB+YEUD3iwIQDKzGAwDQYJ\\r\\n"
    "KoZIhvcNAQELBQADggIBADlPvD6HfkKrfd4BsSyEILpeIROMlw44j/roWuxSPO1G\\r\\n"
    "27A4PrjN03RJxvBr1t0Ke0gDU/tjt3TUqqjkR2eFHRrY/YYzSWo7O2ZfpeLMbusN\\r\\n"
    "bcVFWtzLckTVZWnXZcB2rXbfDgEnUMy+bBQNmMVhJq5EMAY8y7HSgSxJQgDTSbXF\\r\\n"
    "xhsnbPvvXR31aUMQyLTLNIirXYGQjSaCxB9cHkO3UYzW86lpFpoqxMj5lqg+COnl\\r\\n"
    "TITCbwhGbY5WN8eiHmn4E96XHlUMtsWly70LBF0XeY49bI4dhK+SV39RuEtjTD1U\\r\\n"
    "TbJdsOE/UhlSfmjiHme095Exn+hqFZPa35QJTZCIy+Dmzkz3K3tIu47zu80mkGuU\\r\\n"
    "EP/nYcPszrMNaxyGkdFtfgVsJWNZ/9U4bE1WLp1rWUgNLaBV7JeJJUgyBuEU2YyV\\r\\n"
    "AzR0Lf2A2Il6854v75CV5/A9N5HsJdaUlD63whB2dER+FIbG7wjOGml9jEv4xcO5\\r\\n"
    "gNSN0cLGyLBBQD1ny54bJ7uFF2T10kAZNPMVFiMjxcOAvc1zLWoqUmQRl4DNeMom\\r\\n"
    "45E1DwzsJhRLHcGinNTm6dVik+OA1PKrcoEguGPdKE++zff9ikglqOtjLpdVZTvh\\r\\n"
    "CDQnapUVahftzcT/dGwl8/0XOw0Fxogmltg7AbtPpqOy8ohrXDWAplWYLWC00r0M\\r\\n"
    "-----END CERTIFICATE-----\\r\\n";

const std::string kServerKey =
    "-----BEGIN PRIVATE KEY-----\\r\\n"
    "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\\r\\n"
    "yoPPHR2ZQmHEhVRLuyqhRGAGTdHu\\r\\n"
    "-----END PRIVATE KEY-----\\r\\n";

const auto kDispatcherConf = "{\"tls\":{ \"Outgoing\": {\"localhost:8080\": {\"cacrt\": \"\", \"clicrt\": \"\", \"clikey\": \"\"}}, \"Incoming\": {\"*:9000\": { \"cacrt\": \"" + kCACrt + "\", \"clicrt\": \"" + kServerCert + "\", \"clikey\": \"" + kServerKey + "\", \"clientAuth\": false }}}}";

const auto raw = std::make_shared<Sock>();
const auto tls = std::make_shared<edgeless::ttls::TlsSocket>(raw, true);
edgeless::ttls::Dispatcher dis(kDispatcherConf, raw, tls);

int send_hook(int sockfd, void* buf, size_t len, int flags) {
  return dis.Send(sockfd, buf, len, flags);
}

int bind_hook(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  return dis.Bind(sockfd, addr, addrlen);
}

int accept4_hook(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) {
  return dis.Accept4(sockfd, addr, addrlen, flags);
}

int recv_hook(int sockfd, void* buf, size_t len, int flags) {
  return dis.Recv(sockfd, buf, len, flags);
}

int shutdown_hook(int fd, int how) {
  return dis.Shutdown(fd, how);
}

int close_hook(int fd) {
  return dis.Close(fd);
}

long dispatch(long rax, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
  switch (rax) {
    case SYS_bind:
      return bind_hook(arg1, reinterpret_cast<const sockaddr*>(arg2), arg3);
    case SYS_accept4:
      return accept4_hook(arg1, reinterpret_cast<sockaddr*>(arg2), reinterpret_cast<socklen_t*>(arg3), arg4);
    case SYS_write:
      return send_hook(arg1, reinterpret_cast<void*>(arg2), arg3, arg4);
    case SYS_read:
      return recv_hook(arg1, reinterpret_cast<void*>(arg2), arg3, arg4);
    case SYS_shutdown:
      return shutdown_hook(arg1, arg2);
    case SYS_close:
      return close_hook(arg1);
  }
  return (*syscall_func)(rax, arg1, arg2, arg3, arg4, arg5, arg6);
}

int install_hooks() {
  plthook_t* plthook;

  if (plthook_open(&plthook, nullptr) != 0) {
    printf("plthook_open error: %s\n", plthook_error());
    return -1;
  }
  if (plthook_replace(plthook, "syscall", (void*)dispatch, (void**)&syscall_func) != 0) {
    printf("plthook_replace error: %s\n", plthook_error());
    plthook_close(plthook);
    return -1;
  }
  plthook_close(plthook);
  return 0;
}

int main() {
  install_hooks();
  invokemain();
}

#include <plthook/plthook.h>
#include <sys/syscall.h>
#include <ttls/ttls.h>
#include <unistd.h>

#include <cstdarg>
#include <memory>

extern "C" {
void invokemain();
}

using namespace std::string_literals;

static long (*syscall_func)(long int __sysno, ...);
static int (*getaddrinfo_func)(const char* node, const char* service, const addrinfo* hints, addrinfo** res);
class Sock final : public edgeless::ttls::RawSocket {
 public:
  int Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) override {
    return connect(sockfd, addr, addrlen);
  }
  int Accept4(int /*sockfd*/, sockaddr* /*addr*/, socklen_t* /*addrlen*/, int /*flags*/) override {
    return -1;
  }
  int Bind(int /*sockfd*/, const sockaddr* /*addr*/, socklen_t /*addrlen*/) override {
    return -1;
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
  int Getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** res) {
    return (*getaddrinfo_func)(node, service, hints, res);
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

const auto kDispatcherConf = "{\"tls\":{ \"Outgoing\":{\"localhost:9000\": { \"cacrt\": \"" + kCACrt + "\", \"clicrt\": \"\", \"clikey\": \"\" }}}}";

const auto raw = std::make_shared<Sock>();
const auto tls = std::make_shared<edgeless::ttls::MbedtlsSocket>(raw, false);
edgeless::ttls::Dispatcher dis(kDispatcherConf, raw, tls);

int connect_hook(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  return dis.Connect(sockfd, addr, addrlen);
}

int send_hook(int sockfd, void* buf, size_t len, int flags) {
  return dis.Send(sockfd, buf, len, flags);
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

int getaddrinfo_hook(const char* node, const char* service, const addrinfo* hints, addrinfo** res) {
  return dis.Getaddrinfo(node, service, hints, res);
}

int dispatch(long rax, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
  switch (rax) {
    case SYS_connect:
      return connect_hook(arg1, reinterpret_cast<sockaddr*>(arg2), arg3);
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
  if (plthook_replace(plthook, "getaddrinfo", (void*)getaddrinfo_hook, (void**)&getaddrinfo_func) != 0) {
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

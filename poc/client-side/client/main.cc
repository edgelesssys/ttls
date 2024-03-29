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
    "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\\r\\n"
    "7Oe8km7JBDiS8Av4cPe9\\r\\n"
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

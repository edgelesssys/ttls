// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

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

const auto tls = std::make_shared<edgeless::ttls::MbedtlsSocket>();
const auto raw = std::make_shared<edgeless::ttls::RawSocket>();
edgeless::ttls::Dispatcher dis(R"({"tls":["127.0.0.1:9000"]})", raw, tls);

int connect_hook(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  return dis.Connect(sockfd, addr, addrlen);
}

int send_hook(int sockfd, void* buf, size_t len, int flags) {
  return dis.Send(sockfd, buf, len, flags);
}

int recv_hook(int sockfd, void* buf, size_t len, int flags) {
  return dis.Recv(sockfd, buf, len, flags);
}

int close_hook(int fd) {
  return dis.Close(fd);
}

static long (*syscall_func)(long int __sysno, ...);

int dispatch(long rax, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
  switch (rax) {
    case 42:
      return connect_hook(arg1, reinterpret_cast<sockaddr*>(arg2), arg3);
    case 1:
      return send_hook(arg1, reinterpret_cast<void*>(arg2), arg3, arg4);
    case 0:
      return recv_hook(arg1, reinterpret_cast<void*>(arg2), arg3, arg4);
    case 3:
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

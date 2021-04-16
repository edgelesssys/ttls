#include <ttls/libc_socket.h>
#include <unistd.h>

using namespace edgeless::ttls;

int LibcSocket::Close(int fd) {
  return close(fd);
}
int LibcSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  return connect(sockfd, addr, addrlen);
}
ssize_t LibcSocket::Recv(int sockfd, void* buf, size_t len, int /*flags*/) {
  return read(sockfd, buf, len);
}
ssize_t LibcSocket::Send(int sockfd, const void* buf, size_t len, int /*flags*/) {
  return write(sockfd, buf, len);
}
int LibcSocket::Shutdown(int sockfd, int how) {
  return shutdown(sockfd, how);
}
int LibcSocket::Getaddrinfo(const char* node, const char* service, const addrinfo* hints, addrinfo** res) {
  return getaddrinfo(node, service, hints, res);
}

#include <sys/sendfile.h>
#include <sys/uio.h>
#include <ttls/libc_socket.h>
#include <unistd.h>

using namespace edgeless::ttls;

int LibcSocket::Close(int fd) {
  return close(fd);
}

int LibcSocket::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  return connect(sockfd, addr, addrlen);
}

int LibcSocket::Bind(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  return bind(sockfd, addr, addrlen);
}

int LibcSocket::Accept4(int sockfd, sockaddr* addr, socklen_t* addrlen, int flags) {
  return accept4(sockfd, addr, addrlen, flags);
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

ssize_t LibcSocket::Sendfile(int out_fd, int in_fd, off_t* offset, size_t count) {
  return sendfile(out_fd, in_fd, offset, count);
}

ssize_t LibcSocket::Recvfrom(int sockfd, void* __restrict__ buf, size_t len, int flags, struct sockaddr* __restrict__ address, socklen_t* __restrict__ address_len) {
  return recvfrom(sockfd, buf, len, flags, address, address_len);
}

ssize_t LibcSocket::Writev(int fds, const struct iovec* iov, int iovcnt) {
  return writev(fds, iov, iovcnt);
}

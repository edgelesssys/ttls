#include <arpa/inet.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <ttls/libc_socket.h>
#include <ttls/mbedtls_socket.h>
#include <ttls/test_instances.h>

#include <chrono>
#include <condition_variable>
#include <fstream>
#include <thread>

#include "util.h"

using namespace edgeless::ttls;

constexpr std::string_view kRequest = "GET / HTTP/1.0\r\n\r\n";
constexpr std::string_view kResponse = "HTTP/1.0 200 OK\r\n\r\nBody\r\n";

TEST(Mbedtls, Connect) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  TestCredentials credentials;

  auto t1 = StartTestServer("9000", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", credentials.ca_crt, "", ""), 0);
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, ConnectNonBlock) {
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GE(fd, 0);

  TestCredentials credentials;

  auto t1 = StartTestServer("9000", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", credentials.ca_crt, "", ""), 0);
  EXPECT_EQ(0, sock.Shutdown(fd, 2));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, SendAndReceive) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  TestCredentials credentials;

  auto t1 = StartTestServer("9000", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", credentials.ca_crt, "", ""), 0);
  EXPECT_EQ(sock.Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

  std::string buf(4096, ' ');
  EXPECT_GT(sock.Recv(fd, buf.data(), buf.size(), 0), 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, SendAndReceiveNonBlock) {
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GE(fd, 0);

  TestCredentials credentials;

  auto t1 = StartTestServer("9000", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", credentials.ca_crt, "", ""), 0);
  EXPECT_EQ(sock.Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

  std::string buf(4096, ' ');

  int ret = -1;
  do {
    try {
      ret = sock.Recv(fd, buf.data(), buf.size(), 0);
    } catch (const std::exception& e) {
    }
  } while (ret == -1 && errno == EAGAIN);

  EXPECT_GT(ret, 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, ConnectClientAuth) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  TestCredentials credentials;

  auto t1 = StartTestServer("9000", MBEDTLS_SSL_VERIFY_REQUIRED, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", credentials.ca_crt, credentials.cli_crt, credentials.cli_key), 0);
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, ServerSendAndReceiveNonBlock) {
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GE(fd, 0);

  TestCredentials credentials;

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9010);
  ASSERT_EQ(bind(fd, &sock_addr, sizeof(sockaddr)), 0);
  ASSERT_EQ(listen(fd, MBEDTLS_NET_LISTEN_BACKLOG), 0);
  auto t1 = StartTestClient("9010", true, credentials.ca_crt, credentials.cli_crt, credentials.cli_key);

  sockaddr client_sock{};
  socklen_t len = sizeof(sockaddr);
  int client_fd = -1;
  do {
    try {
      client_fd = sock.Accept(fd, &client_sock, &len, 0, credentials.ca_crt, credentials.server_crt, credentials.server_key, true);
    } catch (const std::exception& e) {
    }
  } while (client_fd == -1 && errno == EAGAIN);

  EXPECT_GT(client_fd, 0);

  std::string buf(4096, ' ');
  int ret = -1;
  do {
    try {
      ret = sock.Recv(client_fd, buf.data(), buf.size(), 0);
    } catch (const std::exception& e) {
    }
  } while (ret == -1 && errno == EAGAIN);
  EXPECT_GT(ret, 0);
  EXPECT_EQ(buf.substr(0, 3), "GET");

  do {
    try {
      ret = sock.Send(client_fd, kResponse.data(), kResponse.size(), 0);
    } catch (const std::exception& e) {
    }
  } while (ret == -1 && errno == EAGAIN);

  EXPECT_EQ(0, sock.Shutdown(client_fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(client_fd));

  t1.join();
  EXPECT_EQ(0, close(fd));
}

/*
  Test with the suffix 'Ngx' simmulate nginx behaviour. 
  The tests neither call original nginx functions nor do they implement them.
*/
TEST(Mbedtls, SendfileAndReceiveNgx) {
  const int fd_out = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd_out, 0);

  TestCredentials credentials;

  auto t1 = StartTestServer("9000", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd_out, &sock_addr, sizeof(sock_addr), "", credentials.ca_crt, "", ""), 0);

  // the current dir is {TTLS_BASE}/build
  const char* sample_file = "../src/index.html";

  const std::ifstream file(sample_file);
  ASSERT_EQ(file.good(), true);

  const int fd_in = open(sample_file, O_CLOEXEC);
  ASSERT_GE(fd_in, 4) << "fd has be >= 4, fd = " << fd_in;

  const size_t count = 0xff;
  std::string rbuf(count, ' ');

  // sock.Recv is a 'read' wrapper
  const ssize_t rret = libc_sock->Recv(fd_in, &rbuf[0], count, 0);
  ASSERT_GE(rret, 0);

  const ssize_t sret = sock.Sendfile(fd_out, fd_in, nullptr, count);
  ASSERT_EQ(sret, count);

  libc_sock->Close(fd_in);

  std::string buf(4096, ' ');
  EXPECT_GT(sock.Recv(fd_out, buf.data(), buf.size(), 0), 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Shutdown(fd_out, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd_out));
  t1.join();
}

TEST(Mbedtls, SendAndRecievefromNgx) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  TestCredentials credentials;
  auto t1 = StartTestServer("9000", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", credentials.ca_crt, "", ""), 0);
  EXPECT_EQ(sock.Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

  std::string buf(4096, ' ');
  EXPECT_GT(sock.Recvfrom(fd, buf.data(), buf.size(), 0, nullptr, nullptr), 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, SendAndRecievefromNonBlockNgx) {
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GE(fd, 0);

  TestCredentials credentials;

  auto t1 = StartTestServer("9000", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", credentials.ca_crt, "", ""), 0);
  EXPECT_EQ(sock.Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

  std::string buf(4096, ' ');

  int ret = -1;
  do {
    try {
      ret = sock.Recvfrom(fd, buf.data(), buf.size(), 0, nullptr, nullptr);
    } catch (const std::exception& e) {
    }
  } while (ret == -1 && errno == EAGAIN);

  EXPECT_GT(ret, 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, WritevAndRecvNgx) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  TestCredentials credentials;
  auto t1 = StartTestServer("9000", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock, true);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", credentials.ca_crt, "", ""), 0);

  // not sure yet about the null termination
  struct iovec iov = {};
  std::string req = {kRequest.data()};
  req += '\0';
  iov.iov_base = &req[0];
  iov.iov_len = req.size() + 1;

  EXPECT_EQ(sock.Writev(fd, static_cast<const struct iovec*>(&iov), 1), req.size() + 1);

  std::string buf(4096, ' ');
  int ret = -1;
  do {
    try {
      ret = sock.Recv(fd, buf.data(), buf.size(), 0);
    } catch (const std::exception& e) {
    }
  } while (ret == -1 && errno == EAGAIN);

  EXPECT_GT(ret, 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}
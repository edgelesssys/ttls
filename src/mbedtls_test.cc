#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <ttls/libc_socket.h>
#include <ttls/mbedtls_socket.h>
#include <ttls/test_server.h>

#include <condition_variable>
#include <thread>

#include "util.h"

using namespace edgeless::ttls;

constexpr std::string_view kRequest = "GET / HTTP/1.0\r\n\r\n";

TEST(Mbedtls, Connect) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  auto t1 = StartTestServer(MBEDTLS_SSL_VERIFY_NONE);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", CA_CRT, "", ""), 0);
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, ConnectNonBlock) {
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GE(fd, 0);

  auto t1 = StartTestServer(MBEDTLS_SSL_VERIFY_NONE);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", CA_CRT, "", ""), 0);
  EXPECT_EQ(0, sock.Shutdown(fd, 2));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, SendAndRecieve) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  auto t1 = StartTestServer(MBEDTLS_SSL_VERIFY_NONE);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", CA_CRT, "", ""), 0);
  EXPECT_EQ(sock.Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

  std::string buf(4096, ' ');
  EXPECT_GT(sock.Recv(fd, buf.data(), buf.size(), 0), 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, SendAndRecieveNonBlock) {
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GE(fd, 0);

  auto t1 = StartTestServer(MBEDTLS_SSL_VERIFY_NONE);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", CA_CRT, "", ""), 0);
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

  auto t1 = StartTestServer(MBEDTLS_SSL_VERIFY_REQUIRED);

  const auto libc_sock = std::make_shared<LibcSocket>();
  MbedtlsSocket sock(libc_sock);
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr), "", CA_CRT, CLIENT_CRT, CLIENT_KEY), 0);
  EXPECT_EQ(0, sock.Shutdown(fd, SHUT_RDWR));
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

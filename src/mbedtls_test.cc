#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <ttls/mbedtls_socket.h>

#include <chrono>
#include <condition_variable>
#include <thread>

#include "mock_server.h"
#include "util.h"

using namespace edgeless::ttls;
using namespace std::chrono_literals;

constexpr std::string_view kRequest = "GET / HTTP/1.0\r\n\r\n";

std::thread start_server() {
  std::mutex m;
  std::condition_variable cv;
  bool ready = false;

  std::thread t1(server, std::ref(m), std::ref(cv), std::ref(ready));
  {
    std::unique_lock<std::mutex> lk(m);
    cv.wait(lk, [&] { return ready; });
  }
  return t1;
}

TEST(Mbedtls, Connect) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  auto t1 = start_server();

  MbedtlsSocket sock;
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr)), 0);
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, ConnectNonBlock) {
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GE(fd, 0);

  auto t1 = start_server();

  MbedtlsSocket sock;
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr)), 0);
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, SendAndRecieve) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  auto t1 = start_server();

  MbedtlsSocket sock;
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr)), 0);
  EXPECT_EQ(sock.Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

  std::string buf(4096, ' ');
  EXPECT_GT(sock.Recv(fd, buf.data(), buf.size(), 0), 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, SendAndRecieveNonBlock) {
  const int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  ASSERT_GE(fd, 0);

  auto t1 = start_server();

  MbedtlsSocket sock;
  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 9000);
  EXPECT_EQ(sock.Connect(fd, &sock_addr, sizeof(sock_addr)), 0);
  EXPECT_EQ(sock.Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

  std::string buf(4096, ' ');
  EXPECT_GT(sock.Recv(fd, buf.data(), buf.size(), 0), 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

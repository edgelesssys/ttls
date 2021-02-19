#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <ttls/mbedtls_socket.h>

#include <chrono>
#include <condition_variable>
#include <thread>

#include "mock_server.h"

using namespace edgeless::ttls;
using namespace std::chrono_literals;

constexpr uint16_t kPort = 9000;
constexpr size_t kBufferSize = 4096;
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
  sockaddr_in sock_addr{};
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_port = htons(kPort);
  EXPECT_EQ(1, inet_aton("127.0.0.1", &sock_addr.sin_addr));
  EXPECT_EQ(sock.Connect(fd, reinterpret_cast<sockaddr*>(&sock_addr), sizeof(sock_addr)), 0);
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

TEST(Mbedtls, SendAndRecieve) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(fd, 0);

  auto t1 = start_server();

  MbedtlsSocket sock;
  sockaddr_in sock_addr{};
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_port = htons(kPort);
  EXPECT_EQ(1, inet_aton("127.0.0.1", &sock_addr.sin_addr));
  EXPECT_EQ(sock.Connect(fd, reinterpret_cast<sockaddr*>(&sock_addr), sizeof(sock_addr)), 0);
  EXPECT_EQ(sock.Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

  std::string buf(kBufferSize, ' ');
  EXPECT_GT(sock.Recv(fd, buf.data(), buf.size(), 0), 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Close(fd));
  t1.join();
}

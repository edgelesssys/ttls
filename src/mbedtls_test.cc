#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <ttls/mbedtls_socket.h>

#include <chrono>
#include <thread>

#include "mock_server.h"

using namespace edgeless::ttls;
using namespace std::chrono_literals;

constexpr uint16_t kPort = 9000;
constexpr size_t kBufferSize = 4096;
constexpr std::string_view kRequest = "GET / HTTP/1.0\r\n\r\n";

TEST(Mbedtls, Connect) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);

  std::thread t1(server);
  std::this_thread::sleep_for(1000ms);

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

  std::thread t1(server);
  std::this_thread::sleep_for(1000ms);

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

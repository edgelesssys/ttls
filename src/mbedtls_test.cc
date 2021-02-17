#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <ttls/mbedtls_socket.h>

using namespace edgeless::ttls;

constexpr uint16_t kPort = 9000;
constexpr size_t kBufferSize = 4096;
constexpr std::string_view kRequest = "GET / HTTP/1.0\r\n\r\n";

TEST(Mbedtls, Connect) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);

  MbedtlsSocket sock;
  sockaddr_in sockAddr{};
  sockAddr.sin_family = AF_INET;
  sockAddr.sin_port = htons(kPort);
  EXPECT_EQ(1, inet_aton("127.0.0.1", &sockAddr.sin_addr));
  EXPECT_EQ(sock.Connect(fd, reinterpret_cast<sockaddr*>(&sockAddr), sizeof(sockAddr)), 0);
  EXPECT_EQ(0, sock.Close(fd));
}

TEST(Mbedtls, SendAndRecieve) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);

  MbedtlsSocket sock;
  sockaddr_in sockAddr{};
  sockAddr.sin_family = AF_INET;
  sockAddr.sin_port = htons(kPort);
  EXPECT_EQ(1, inet_aton("127.0.0.1", &sockAddr.sin_addr));
  EXPECT_EQ(sock.Connect(fd, reinterpret_cast<sockaddr*>(&sockAddr), sizeof(sockAddr)), 0);
  EXPECT_EQ(sock.Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

  std::string buf = std::string(kBufferSize, ' ');
  EXPECT_GT(sock.Recv(fd, buf.data(), buf.size(), 0), 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  EXPECT_EQ(0, sock.Close(fd));
}

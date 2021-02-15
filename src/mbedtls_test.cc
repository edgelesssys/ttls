#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <ttls/mbedtls_socket.h>

#include <memory>

#include "mock_socket.h"

using namespace std;
using namespace edgeless::ttls;

constexpr int MY_PORT = 9000;
constexpr int BUF_SIZE = 4096;
constexpr std::string_view req = "GET / HTTP/1.0\r\n\r\n";

TEST(MBEDTLS, connect) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);

  auto sock = std::make_unique<MbedtlsSocket>();
  sockaddr_in sockAddr = sockaddr_in();
  sockAddr.sin_family = AF_INET;
  sockAddr.sin_port = htons(MY_PORT);
  inet_aton("127.0.0.1", &sockAddr.sin_addr);
  EXPECT_EQ(sock->Connect(fd, (struct sockaddr*)&sockAddr, sizeof(sockAddr)), 0);
  sock->Close(fd);
}

TEST(MBEDTLS, sendAndRecieve) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);

  auto sock = std::make_unique<MbedtlsSocket>();
  sockaddr_in sockAddr = sockaddr_in();
  sockAddr.sin_family = AF_INET;
  sockAddr.sin_port = htons(MY_PORT);
  inet_aton("127.0.0.1", &sockAddr.sin_addr);
  EXPECT_EQ(sock->Connect(fd, (struct sockaddr*)&sockAddr, sizeof(sockAddr)), 0);
  EXPECT_EQ(sock->Send(fd, &req[0], req.size(), 0), req.size());

  std::string buf = std::string(BUF_SIZE, ' ');
  EXPECT_GT(sock->Recv(fd, &buf[0], buf.size(), 0), 0);
  EXPECT_EQ(buf.substr(9, 6), "200 OK");
  sock->Close(fd);
}

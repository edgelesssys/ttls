#include <gtest/gtest.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ttls/dispatcher.h>

#include <memory>

#include "mock_socket.h"
#include "util.h"

using namespace edgeless::ttls;
using namespace std::string_literals;

TEST(Dispatcher, InvalidConfigString) {
  const auto sock = std::make_shared<MockSocket>();
  EXPECT_THROW(Dispatcher("", sock, sock), std::runtime_error);
  EXPECT_THROW(Dispatcher("foo", sock, sock), std::runtime_error);
}

TEST(Dispatcher, EmptyConfig) {
  const auto raw = std::make_shared<MockSocket>();
  const auto tls = std::make_shared<MockSocket>();
  const int tls_fd = 3;

  Dispatcher dispatcher(R"({"tls":[]})", raw, tls);

  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 443);

  EXPECT_EQ(0, dispatcher.Connect(tls_fd, &sock_addr, sizeof(sock_addr)));

  // expect call is not forwarded to tls function
  EXPECT_TRUE(tls->connections.empty());

  // expect call is forwarded to raw function
  ASSERT_EQ(1, raw->connections.size());

  const auto& args = raw->connections.at(tls_fd);
  EXPECT_EQ(&sock_addr, args.addr);
  EXPECT_EQ(sizeof(sock_addr), args.addrlen);

  EXPECT_EQ(0, dispatcher.Shutdown(tls_fd, 2));
  EXPECT_EQ(0, dispatcher.Close(tls_fd));
  EXPECT_EQ(0, raw->connections.size());
}

TEST(Dispatcher, ForwardConfig) {
  const auto raw = std::make_shared<MockSocket>();
  const auto tls = std::make_shared<MockSocket>();
  const int tls_fd = 4;

  Dispatcher dispatcher(R"({"tls":["127.0.0.1:443", "192.168.0.1:80"]})", raw, tls);

  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 443);

  EXPECT_EQ(0, dispatcher.Connect(tls_fd, &sock_addr, sizeof(sock_addr)));

  // expect call is forwarded to tls function
  ASSERT_EQ(1, tls->connections.size());

  const auto& args = tls->connections.at(tls_fd);
  EXPECT_EQ(&sock_addr, args.addr);
  EXPECT_EQ(sizeof(sock_addr), args.addrlen);

  // expect call is not forwarded to raw function
  EXPECT_TRUE(raw->connections.empty());

  const std::string msg("Test");
  EXPECT_EQ(msg.size(), dispatcher.Send(tls_fd, msg.data(), msg.size(), 0));

  // expect data is send to tls socket
  const std::string msg_buf_str(args.msg_buf.cbegin(), args.msg_buf.cend());
  EXPECT_EQ(msg, msg_buf_str);

  std::string recv_msg(1024, ' ');
  const int ret_len = dispatcher.Recv(tls_fd, recv_msg.data(), recv_msg.size(), 0);
  recv_msg.erase(recv_msg.find(' '));
  EXPECT_EQ(recv_msg.size(), ret_len);

  // expect data is received
  EXPECT_EQ(recv_msg, "OK-" + msg);

  EXPECT_EQ(0, dispatcher.Shutdown(tls_fd, 2));
  EXPECT_EQ(0, dispatcher.Close(tls_fd));
}

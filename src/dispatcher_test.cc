#include <gtest/gtest.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ttls/dispatcher.h>

#include <memory>
#include <nlohmann/json.hpp>

#include "mock_socket.h"

using namespace std;
using namespace edgeless::ttls;
using namespace std::string_literals;

TEST(Dispatcher, InvalidConfigString) {
  const auto sock = make_shared<MockSocket>();
  EXPECT_THROW(Dispatcher("", sock, sock), runtime_error);
  EXPECT_THROW(Dispatcher("foo", sock, sock), runtime_error);
}

TEST(Dispatcher, EmptyConfig) {
  const auto raw = make_shared<MockSocket>();
  const auto tls = make_shared<MockSocket>();
  const int tls_fd = 3;

  Dispatcher dispatcher(R"({"tls":[]})", raw, tls);

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_NUMERICHOST;
  hints.ai_flags |= AI_NUMERICSERV;

  addrinfo* res = nullptr;
  getaddrinfo("127.0.0.1", "443", &hints, &res);

  raw->connect_ret = 2;
  EXPECT_EQ(2, dispatcher.Connect(tls_fd, res->ai_addr, res->ai_addrlen));

  // expect call is not forwarded to tls function
  EXPECT_TRUE(tls->connect.empty());

  // expect call is forwarded to raw function
  ASSERT_EQ(1, raw->connect.size());
  EXPECT_NO_THROW(raw->connect.at(tls_fd));

  const auto& args = raw->connect.at(tls_fd);
  EXPECT_EQ(res->ai_addr, args.first);
  EXPECT_EQ(res->ai_addrlen, args.second);

  EXPECT_EQ(0, dispatcher.Close(tls_fd));
  EXPECT_EQ(0, raw->connect.size());
  freeaddrinfo(res);
}

TEST(Dispatcher, ForwardConfig) {
  const auto raw = make_shared<MockSocket>();
  const auto tls = make_shared<MockSocket>();
  const int tls_fd = 4;

  Dispatcher dispatcher(R"({"tls":["127.0.0.1:443", "192.168.0.1:80"]})", raw, tls);
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_NUMERICHOST;
  hints.ai_flags |= AI_NUMERICSERV;

  addrinfo* res = nullptr;
  getaddrinfo("127.0.0.1", "443", &hints, &res);

  tls->connect_ret = 2;
  EXPECT_EQ(2, dispatcher.Connect(tls_fd, res->ai_addr, res->ai_addrlen));

  // expect call is forwarded to tls function
  ASSERT_EQ(1, tls->connect.size());
  EXPECT_NO_THROW(tls->connect.at(tls_fd));

  const auto& args = tls->connect.at(tls_fd);
  EXPECT_EQ(res->ai_addr, args.first);
  EXPECT_EQ(res->ai_addrlen, args.second);

  // expect call is not forwarded to raw function
  EXPECT_TRUE(raw->connect.empty());

  const std::string msg("Test");
  EXPECT_EQ(msg.size(), dispatcher.Send(tls_fd, msg.data(), msg.size(), 0));

  // expect data is send to tls socket
  EXPECT_NO_THROW(tls->msg_buf.at(tls_fd));
  const auto& msg_buf = tls->msg_buf.at(tls_fd);
  const std::string msg_buf_str(msg_buf.begin(), msg_buf.end());
  EXPECT_EQ(msg, msg_buf_str);

  // expect data is not send to raw socket
  EXPECT_THROW(raw->msg_buf.at(tls_fd), std::out_of_range);

  std::string recv_msg(1024, ' ');
  const int ret_len = dispatcher.Recv(tls_fd, recv_msg.data(), recv_msg.size(), 0);
  recv_msg = recv_msg.substr(0, recv_msg.find(' '));
  EXPECT_EQ(recv_msg.size(), ret_len);

  // expect data is received
  EXPECT_EQ(recv_msg, "OK-" + msg);

  EXPECT_EQ(0, dispatcher.Close(tls_fd));
  freeaddrinfo(res);
}

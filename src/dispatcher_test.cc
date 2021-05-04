#include <gtest/gtest.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ttls/dispatcher.h>

#include <algorithm>
#include <iterator>
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

  Dispatcher dispatcher(R"({"tls": {"Incoming":{}, "Outgoing": {} }})", raw, tls);

  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 443);

  EXPECT_EQ(0, dispatcher.Connect(tls_fd, &sock_addr, sizeof(sock_addr)));

  // expect call is not forwarded to tls function
  EXPECT_TRUE(tls->connections.empty());

  // expect call is forwarded to raw function
  ASSERT_EQ(1, raw->connections.size());

  const auto& args = raw->connections.at(tls_fd);
  EXPECT_EQ(&sock_addr, args.addr);
  EXPECT_EQ(sizeof(sock_addr), args.addrlen);

  EXPECT_EQ(0, dispatcher.Shutdown(tls_fd, SHUT_RDWR));
  EXPECT_EQ(0, dispatcher.Close(tls_fd));
  EXPECT_EQ(0, raw->connections.size());
}

TEST(Dispatcher, ClientForwardConfig) {
  const auto raw = std::make_shared<MockSocket>();
  const auto tls = std::make_shared<MockSocket>();
  const int tls_fd = 4;

  Dispatcher dispatcher(R"({"tls":{"Outgoing":{"127.0.0.1:443":{"cacrt": "CA_CRT", "clicert": "", "clikey": ""},"192.168.0.1:80": {"cacrt" : "DIFF_CA_CRT", "clicert": "", "clikey": ""}}, "Incoming" : {"111.111.111.111:22": { "cacrt": "CA_CRT", "clicert": "SERVER_CRT", "clikey": "" }}}})",
                        raw, tls);

  sockaddr sock_addr = MakeSockaddr("127.0.0.1", 443);

  EXPECT_EQ(0, dispatcher.Connect(tls_fd, &sock_addr, sizeof(sock_addr)));

  // expect call is forwarded to tls function
  ASSERT_EQ(1, tls->connections.size());

  const auto& args = tls->connections.at(tls_fd);
  EXPECT_EQ(&sock_addr, args.addr);
  EXPECT_EQ(sizeof(sock_addr), args.addrlen);
  EXPECT_EQ("CA_CRT", args.ca_crt);

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

  EXPECT_EQ(0, dispatcher.Shutdown(tls_fd, SHUT_RDWR));
  EXPECT_EQ(0, dispatcher.Close(tls_fd));
}

TEST(Dispatcher, ForwardConfigDomains) {
  const auto raw = std::make_shared<MockSocket>();
  const auto tls = std::make_shared<MockSocket>();
  const int tls_fd = 4;

  Dispatcher dispatcher(R"({"tls":{ "Outgoing": {"service.name:443": {"cacrt" : "CA_CRT", "clicert": "", "clikey": ""} , "other.service.name:80": {"cacrt" : "DIFF_CA_CRT", "clicert": "", "clikey": ""}}}})", raw, tls);

  sockaddr sock_addr = MakeSockaddr("133.133.133.133", 443);

  addrinfo* result = nullptr;
  EXPECT_EQ(0, dispatcher.Getaddrinfo("service.name", nullptr, nullptr, &result));

  EXPECT_EQ(0, dispatcher.Connect(tls_fd, &sock_addr, sizeof(sock_addr)));

  // expect call is forwarded to tls function
  ASSERT_EQ(1, tls->connections.size());

  const auto& args = tls->connections.at(tls_fd);
  EXPECT_EQ(&sock_addr, args.addr);
  EXPECT_EQ(sizeof(sock_addr), args.addrlen);
  EXPECT_EQ("CA_CRT", args.ca_crt);

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

  EXPECT_EQ(0, dispatcher.Shutdown(tls_fd, SHUT_RDWR));
  EXPECT_EQ(0, dispatcher.Close(tls_fd));
}

TEST(Dispatcher, ServerForwardConfig) {
  const auto raw = std::make_shared<MockSocket>();
  const auto tls = std::make_shared<MockSocket>();
  const int tls_fd = 4;

  Dispatcher dispatcher(R"({"tls":{"Outgoing":{"127.0.0.1:443":{"cacrt": "CA_CRT", "clicert": "", "clikey": ""},"192.168.0.1:80": {"cacrt" : "DIFF_CA_CRT", "clicert": "", "clikey": ""}}, "Incoming" : {"111.111.111.111:22": { "cacrt": "CA_CRT", "clicert": "SERVER_CRT", "clikey": "SERVER_KEY" }}}})",
                        raw, tls);

  sockaddr sock_addr{};
  socklen_t len = sizeof(sockaddr);
  // EXPECT_EQ(tls_fd, dispatcher.Accept4(tls_fd, nullptr, nullptr, 0));
  EXPECT_EQ(tls_fd, dispatcher.Accept4(tls_fd, &sock_addr, &len, 0));

  // expect the correct sockaddr is returned
  auto expect_addr = MakeSockaddr("111.111.111.111", 22);
  EXPECT_TRUE(std::equal(std::begin(sock_addr.sa_data), std::end(sock_addr.sa_data), std::begin(expect_addr.sa_data)));
  EXPECT_EQ(len, sizeof(sockaddr));

  // expect call is forwarded to tls function
  EXPECT_EQ(1, tls->connections.size());

  const auto& args = tls->connections.at(tls_fd);
  EXPECT_EQ(false, args.outgoing);
  EXPECT_EQ(nullptr, args.addr);
  EXPECT_EQ("CA_CRT", args.ca_crt);
  EXPECT_EQ("SERVER_CRT", args.client_crt);
  EXPECT_EQ("SERVER_KEY", args.client_key);

  // expect raw was used to accept the connection
  EXPECT_EQ(1, raw->connections.size());

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

  EXPECT_EQ(0, dispatcher.Shutdown(tls_fd, SHUT_RDWR));
  EXPECT_EQ(0, dispatcher.Close(tls_fd));
}

TEST(Dispatcher, ServerForwardConfigAcceptNullptr) {
  const auto raw = std::make_shared<MockSocket>();
  const auto tls = std::make_shared<MockSocket>();
  const int tls_fd = 4;

  Dispatcher dispatcher(R"({"tls":{"Outgoing":{"127.0.0.1:443":{"cacrt": "CA_CRT", "clicert": "", "clikey": ""},"192.168.0.1:80": {"cacrt" : "DIFF_CA_CRT", "clicert": "", "clikey": ""}}, "Incoming" : {"111.111.111.111:22": { "cacrt": "CA_CRT", "clicert": "SERVER_CRT", "clikey": "SERVER_KEY" }}}})",
                        raw, tls);

  EXPECT_EQ(tls_fd, dispatcher.Accept4(tls_fd, nullptr, nullptr, 0));

  // expect call is forwarded to tls function
  EXPECT_EQ(1, tls->connections.size());

  EXPECT_EQ(0, dispatcher.Shutdown(tls_fd, SHUT_RDWR));
  EXPECT_EQ(0, dispatcher.Close(tls_fd));
}

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

  Dispatcher dispatcher(R"({"tls":[]})", raw, tls);

  raw->connect_ret = 2;
  EXPECT_EQ(2, dispatcher.Connect(3, nullptr, 4));

  // expect call is not forwarded to tls function
  EXPECT_TRUE(tls->connect.empty());

  // expect call is forwarded to raw function
  ASSERT_EQ(1, raw->connect.size());
  const auto& args = raw->connect[0];
  EXPECT_EQ(3, get<0>(args));
  EXPECT_EQ(nullptr, get<1>(args));
  EXPECT_EQ(4, get<2>(args));
}

TEST(Dispatcher, ForwardConfig) {
  const auto raw = make_shared<MockSocket>();
  const auto tls = make_shared<MockSocket>();

  Dispatcher dispatcher(R"({"tls":["127.0.0.1:443", "192.168.0.1:80"]})", raw, tls);
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_NUMERICHOST;
  hints.ai_flags |= AI_NUMERICSERV;

  addrinfo* res{};
  getaddrinfo("127.0.0.1", "443", &hints, &res);

  raw->connect_ret = 2;
  EXPECT_EQ(2, dispatcher.Connect(3, reinterpret_cast<sockaddr*>(res), sizeof(sockaddr)));

  // expect call is forwarded to tls function
  ASSERT_EQ(1, tls->connect.size());
  const auto& args = tls->connect[0];
  EXPECT_EQ(3, get<0>(args));
  EXPECT_EQ(nullptr, get<1>(args));
  EXPECT_EQ(4, get<2>(args));

  // expect call is not forwarded to raw function
  EXPECT_TRUE(raw->connect.empty());
}

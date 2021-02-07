#include <gtest/gtest.h>
#include <ttls/dispatcher.h>

#include <memory>

#include "mock_socket.h"

using namespace std;
using namespace edgeless::ttls;

TEST(Dispatcher, InvalidConfigString) {
  const auto sock = make_shared<MockSocket>();
  EXPECT_THROW(Dispatcher("", sock, sock), runtime_error);
  EXPECT_THROW(Dispatcher("foo", sock, sock), runtime_error);
}

TEST(Dispatcher, EmptyConfig) {
  const auto raw = make_shared<MockSocket>();
  const auto tls = make_shared<MockSocket>();

  Dispatcher dispatcher("{}", raw, tls);

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

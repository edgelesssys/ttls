#include <gtest/gtest.h>
#include <ttls/dispatcher.h>
#include <ttls/libc_socket.h>
#include <ttls/mbedtls_socket.h>
#include <ttls/test_instances.h>

#include <thread>

#include "util.h"

using namespace edgeless::ttls;

TEST(Race, Client) {
  const auto raw = std::make_shared<LibcSocket>();
  const auto tls = std::make_shared<MbedtlsSocket>(raw, false);

  TestCredentials credentials;
  const std::string ca_crt_encoded = JSONescape(credentials.ca_crt);

  const std::string config =
      R"({
            "tls":
            {
                "Outgoing":
                {
                    "localhost:9020":
                        {
                            "cacrt": ")" +
      ca_crt_encoded + R"(",
         "clicrt":"",
          "clikey":""
                        },
                    "localhost:9030":
                        {
                            "cacrt": ")" +
      ca_crt_encoded + R"(",
         "clicrt":"",
          "clikey":""
                        },
                    "localhost:9040":
                        {
                            "cacrt": ")" +
      ca_crt_encoded + R"(",
         "clicrt":"",
          "clikey":""
                        },
                    "localhost:9050":
                        {
                            "cacrt": ")" +
      ca_crt_encoded + R"(",
         "clicrt":"",
          "clikey":""
                        }
                }
            }
        })";
  auto dis = std::make_unique<Dispatcher>(config, raw, tls);

  constexpr std::string_view kRequest = "GET / HTTP/1.0\r\n\r\n";

  auto client_func = [&](auto port) {
    const auto sock_addr = MakeSockaddr("127.0.0.1", port);
    const int fd = socket(AF_INET, SOCK_STREAM, 0);

    addrinfo* result = nullptr;
    EXPECT_EQ(dis->Getaddrinfo("localhost", nullptr, nullptr, &result), 0);
    freeaddrinfo(result);
    EXPECT_EQ(dis->Connect(fd, &sock_addr, sizeof(sock_addr)), 0);
    EXPECT_EQ(dis->Send(fd, kRequest.data(), kRequest.size(), 0), kRequest.size());

    std::string buf(4096, ' ');
    EXPECT_GT(dis->Recv(fd, buf.data(), buf.size(), 0), 0);
    EXPECT_EQ(buf.substr(9, 6), "200 OK");

    EXPECT_EQ(0, dis->Shutdown(fd, SHUT_RDWR));
    EXPECT_EQ(0, dis->Close(fd));
  };

  auto t1 = StartTestServer("9020", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);
  auto t2 = StartTestServer("9030", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);
  auto t3 = StartTestServer("9040", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);
  auto t4 = StartTestServer("9050", MBEDTLS_SSL_VERIFY_NONE, credentials.ca_crt, credentials.server_crt, credentials.server_key);

  auto t5 = std::thread(client_func, 9020);
  auto t6 = std::thread(client_func, 9030);
  auto t7 = std::thread(client_func, 9040);
  auto t8 = std::thread(client_func, 9050);

  t1.join();
  t2.join();
  t3.join();
  t4.join();
  t5.join();
  t6.join();
  t7.join();
  t8.join();
}

TEST(Race, Server) {
  const auto raw = std::make_shared<LibcSocket>();
  const auto tls = std::make_shared<MbedtlsSocket>(raw, false);

  TestCredentials credentials;
  const std::string ca_crt_encoded = JSONescape(credentials.ca_crt);
  const std::string server_crt_encoded = JSONescape(credentials.server_crt);
  const std::string server_key_encoded = JSONescape(credentials.server_key);

  const std::string config =
      R"({
            "tls":
            {
                "Incoming":
                {
                    "*:9060":
                        {
                            "cacrt": ")" +
      ca_crt_encoded + R"(",
         "clicrt":")" +
      server_crt_encoded + R"(",
          "clikey":")" +
      server_key_encoded + R"(",
          "clientAuth": true
                        },
                    "*:9070":
                        {
                            "cacrt": ")" +
      ca_crt_encoded + R"(",
         "clicrt":")" +
      server_crt_encoded + R"(",
          "clikey":")" +
      server_key_encoded + R"(",
          "clientAuth": true
                        },
                    "*:9080":
                        {
                            "cacrt": ")" +
      ca_crt_encoded + R"(",
         "clicrt":")" +
      server_crt_encoded + R"(",
          "clikey":")" +
      server_key_encoded + R"(",
          "clientAuth": true
                        },
                    "*:9090":
                        {
                            "cacrt": ")" +
      ca_crt_encoded + R"(",
         "clicrt":")" +
      server_crt_encoded + R"(",
          "clikey":")" +
      server_key_encoded + R"(",
          "clientAuth": true
                        }
                }
            }
        })";
  auto dis = std::make_unique<Dispatcher>(config, raw, tls);

  auto server_func = [&](int port) {
    constexpr std::string_view kResponse = "HTTP/1.0 200 OK\r\n\r\nBody\r\n";

    const auto sock_addr = MakeSockaddr("127.0.0.1", port);
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GT(fd, 0);

    ASSERT_EQ(dis->Bind(fd, &sock_addr, sizeof(sockaddr)), 0);
    ASSERT_EQ(listen(fd, 10), 0);

    auto t1 = StartTestClient(std::to_string(port), true, credentials.ca_crt, credentials.cli_crt, credentials.cli_key);

    int client_fd = -1;
    do {
      client_fd = dis->Accept4(fd, nullptr, nullptr, 0);
    } while (client_fd == -1 && errno == EAGAIN);
    EXPECT_GT(client_fd, 0);

    std::string buf(4096, ' ');
    int ret = -1;
    do {
      ret = dis->Recv(client_fd, buf.data(), buf.size(), 0);
    } while (ret == -1 && errno == EAGAIN);
    EXPECT_GT(ret, 0);

    do {
      ret = dis->Send(client_fd, kResponse.data(), kResponse.size(), 0);
    } while (ret == -1 && errno == EAGAIN);
    EXPECT_EQ(ret, kResponse.size());

    EXPECT_EQ(dis->Shutdown(client_fd, SHUT_RDWR), 0);
    EXPECT_EQ(dis->Close(client_fd), 0);

    t1.join();
    EXPECT_EQ(close(fd), 0);
  };

  auto t2 = std::thread(server_func, 9060);
  auto t3 = std::thread(server_func, 9070);
  auto t4 = std::thread(server_func, 9080);
  auto t5 = std::thread(server_func, 9090);

  t2.join();
  t3.join();
  t4.join();
  t5.join();
}

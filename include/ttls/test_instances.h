#pragma once

#include <string>
#include <thread>

namespace edgeless::ttls {

/**
 * Starts a tls test server and waits for it to be ready.
 * @param port set the listening port
 * @param client_auth set 0 to disable and 2 to require client auth
 * @return newly created thread
 */
std::thread StartTestServer(const std::string& port, int client_auth, const std::string& ca_crt, const std::string& server_crt, const std::string& server_key);

/**
 * Starts a tls test client. The server must already be listening.
 * @param port set port the client connects to
 * @param client_auth set to require client auth
 * @return newly created thread
 */
std::thread StartTestClient(const std::string& port, bool client_auth, const std::string& ca_crt, const std::string& cli_crt, const std::string& cli_key);

struct TestCredentials {
  std::string ca_crt, server_crt, server_key, cli_crt, cli_key;
  TestCredentials();
};

std::string JSONescape(const std::string& s);
}  // namespace edgeless::ttls

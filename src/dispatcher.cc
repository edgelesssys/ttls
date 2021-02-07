#include "dispatcher.h"

#include <cassert>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>

using namespace std;
using namespace edgeless::ttls;

Dispatcher::Dispatcher(std::string_view config, const SocketPtr& raw, const SocketPtr& tls)
    : raw_(raw), tls_(tls) {
  assert(raw);
  assert(tls);

  // parse config
  try {
    config_ = make_unique<nlohmann::json>(nlohmann::json::parse(config));
  } catch (const nlohmann::json::exception& e) {
    throw runtime_error("dispatcher: cannot parse config: "s + e.what());
  }
}

Dispatcher::~Dispatcher() = default;

int Dispatcher::Connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
  // TODO check config to decide whether this should be wrapped in TLS
  return raw_->Connect(sockfd, addr, addrlen);
}

const nlohmann::json& Dispatcher::Conf() const noexcept {
  return *config_;
}

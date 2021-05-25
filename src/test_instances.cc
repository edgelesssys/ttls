#include "test_instances.h"

#include <condition_variable>
#include <mutex>

using namespace edgeless;

extern "C" int edgeless_ttls_test_server(void notify(void*), void* event, const char* srv_crt, const char* cas_pem, const char* srv_key, const char* port, int client_auth);
extern "C" int edgeless_ttls_test_client(const char* srv_crt, const char* cas_pem, const char* srv_key, const char* port, bool client_auth);

namespace {
struct Event {
  std::mutex m;
  std::condition_variable cv;
  bool ready;
};
}  // namespace

static void Notify(void* event) {
  auto& ev = *static_cast<Event*>(event);

  const std::lock_guard lock(ev.m);
  ev.ready = true;
  ev.cv.notify_one();
}

std::thread ttls::StartTestServer(const std::string& port, int client_auth) {
  Event ev{};
  std::thread t1(edgeless_ttls_test_server, Notify, &ev, SERVER_CRT.c_str(), CA_CRT.c_str(), SERVER_KEY.c_str(), port.c_str(), client_auth);
  {
    std::unique_lock<std::mutex> lk(ev.m);
    ev.cv.wait(lk, [&] { return ev.ready; });
  }
  return t1;
}

std::thread ttls::StartTestClient(const std::string& port, bool client_auth) {
  return std::thread(edgeless_ttls_test_client, CLIENT_CRT.c_str(), CA_CRT.c_str(), CLIENT_KEY.c_str(), port.c_str(), client_auth);
}

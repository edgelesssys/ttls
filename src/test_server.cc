#include "test_server.h"

#include <condition_variable>
#include <mutex>

using namespace edgeless;

extern "C" int edgeless_ttls_test_server(void notify(void*), void* event, const char* srv_crt, const char* cas_pem, const char* srv_key);

namespace {
struct Event {
  std::mutex m;
  std::condition_variable cv;
  bool ready;
};
}  // namespace

static void Notify(void* event) {
  auto& ev = *static_cast<Event*>(event);

  {
    const std::lock_guard lock(ev.m);
    ev.ready = true;
  }

  ev.cv.notify_one();
}

std::thread ttls::StartTestServer() {
  Event ev{};
  std::thread t1(edgeless_ttls_test_server, Notify, &ev, SERVER_CRT.c_str(), CA_CRT.c_str(), SERVER_KEY.c_str());
  {
    std::unique_lock<std::mutex> lk(ev.m);
    ev.cv.wait(lk, [&] { return ev.ready; });
  }
  return t1;
}

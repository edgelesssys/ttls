#pragma once

#include <condition_variable>
#include <mutex>

namespace edgeless::ttls {
int server(std::mutex& m, std::condition_variable& cv, bool& ready);
}  // namespace edgeless::ttls

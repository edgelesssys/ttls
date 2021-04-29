#include <plthook/plthook.h>
#include <sys/syscall.h>
#include <ttls/ttls.h>
#include <unistd.h>

#include <cstdarg>
#include <memory>

extern "C" {
void invokemain();
}

int main() {
  invokemain();
}

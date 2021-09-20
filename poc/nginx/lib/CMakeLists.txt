cmake_minimum_required(VERSION 3.11)
project(poc_ngx)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -pedantic -Werror)
#set(CMAKE_CXX_CLANG_TIDY clang-tidy-10)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)


#
# plthook library
#

add_library(plt
  plthook_elf.c)

target_include_directories(plt
  PRIVATE include/plthook
)

link_directories(../../../build)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif ()

#
# build loader
#

add_library(loader SHARED loader.cc)
set_property(TARGET loader PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(loader 
  PRIVATE ${CMAKE_SOURCE_DIR}/include
  ../../../include
  ../../../3rdparty/nlohmann/include)

target_link_libraries(plt dl)
target_link_libraries(loader ttls plt Threads::Threads mbedtls mbedx509 mbedcrypto)
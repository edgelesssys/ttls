cmake_minimum_required(VERSION 3.10)
project(ttls)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -pedantic -Werror)

if(NOT TTLS_NOTEST)
  execute_process(
    COMMAND git submodule update --init 3rdparty/googletest
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  set(GOOGLETEST_VERSION 1.10.0)
  add_subdirectory(3rdparty/googletest/googletest)

  set(CMAKE_CXX_CLANG_TIDY clang-tidy-10)

  if(TTLS_ASAN)
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all)
    add_link_options(-fsanitize=address,undefined)
  elseif(TTLS_TSAN OR CMAKE_BUILD_TYPE STREQUAL Debug)
    add_compile_options(-fsanitize=thread)
    add_link_options(-fsanitize=thread)
  endif()
endif()

#
# ttls library
#

add_library(ttlsobj OBJECT
  src/dispatcher.cc
  src/mbedtls_socket.cc
  src/test_instances.cc
  3rdparty/mbedtls/ssl_server.c
  3rdparty/mbedtls/ssl_client.c)

set_property(TARGET ttlsobj PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(ttlsobj
  PUBLIC include 3rdparty/nlohmann/include
  PRIVATE include/ttls)

add_library(ttls)
target_link_libraries(ttls ttlsobj)

#
# test
#

if(NOT TTLS_NOTEST)
  add_executable(ttls_test
    src/libc_socket.cc
    src/dispatcher_test.cc
    src/mbedtls_test.cc
    src/util.cc
    src/race_tests.cc)

  target_link_libraries(ttls_test ttls gtest_main mbedtls mbedx509 mbedcrypto)

  include(GoogleTest)
  enable_testing()
  gtest_discover_tests(ttls_test)
endif()

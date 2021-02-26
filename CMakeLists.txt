cmake_minimum_required(VERSION 3.10)
project(ttls)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

execute_process(
  COMMAND git submodule update --init 3rdparty/googletest
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -pedantic -Werror)

set(GOOGLETEST_VERSION 1.10.0)
add_subdirectory(3rdparty/googletest/googletest)

set(CMAKE_CXX_CLANG_TIDY clang-tidy-10)

#
# ttls library
#

add_library(ttls
  src/dispatcher.cc
  src/mbedtls_socket.cc
  src/raw_socket.cc)

target_include_directories(ttls
  PUBLIC include
  PRIVATE include/ttls)

#
# test
#
add_custom_command(
  OUTPUT server.crt
  COMMAND openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt -days 365
  -subj "/C=US/ST=State/L=City/O=Org/OU=Org/CN=Test CA"
  -addext "subjectAltName = DNS:localhost"
  COMMAND openssl req -new -newkey rsa:4096 -nodes -keyout server.key -out server.csr -days 365
  -subj "/C=US/ST=State/L=City/O=Org/OU=Org/CN=localhost"
  -addext "subjectAltName = DNS:localhost"
  COMMAND openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
)
add_custom_target(certs DEPENDS server.crt)

add_executable(ttls_test
  src/dispatcher_test.cc
  src/mbedtls_test.cc
  src/util.cc)

add_library(ttls_test_notidy
  src/mock_server.cpp)

set_target_properties(ttls_test_notidy PROPERTIES CXX_CLANG_TIDY "")

add_dependencies(ttls_test certs)

target_link_libraries(ttls_test ttls_test_notidy ttls gtest_main mbedtls mbedx509 mbedcrypto)

include(GoogleTest)
enable_testing()
gtest_discover_tests(ttls_test)

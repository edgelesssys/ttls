cmake_minimum_required(VERSION 3.10)
project(ttls)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

execute_process(
  COMMAND git submodule update --init 3rdparty/googletest
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -pedantic -Werror)

set(GOOGLETEST_VERSION 1.10.0)
add_subdirectory(3rdparty/googletest/googletest)

set(CMAKE_CXX_CLANG_TIDY clang-tidy-10)

add_library(ttls_test_notidy OBJECT
  src/test_server.cpp)

#
# test server
#
target_include_directories(ttls_test_notidy
  PUBLIC include
  PRIVATE include/ttls)
set_property(TARGET ttls_test_notidy PROPERTY POSITION_INDEPENDENT_CODE ON)

set_target_properties(ttls_test_notidy PROPERTIES CXX_CLANG_TIDY "")

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

add_executable(ttls_test
  src/dispatcher_test.cc
  src/mbedtls_test.cc
  src/util.cc)

target_link_libraries(ttls_test ttls gtest_main mbedtls mbedx509 mbedcrypto)


include(GoogleTest)
enable_testing()
gtest_discover_tests(ttls_test)

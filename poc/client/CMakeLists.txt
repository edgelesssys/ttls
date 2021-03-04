# Copyright (c) Edgeless Systems GmbH.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)
project(poc)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -pedantic -Werror)

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


link_directories(../../build)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif ()

add_custom_target(
  app ertgo build -buildmode=c-archive ${CMAKE_SOURCE_DIR}/app)


add_executable(client main.cc)
target_include_directories(client
  PRIVATE ${CMAKE_SOURCE_DIR}/include ../../include)
add_dependencies(client app)

target_link_libraries(plt dl)
target_link_libraries(client plt ${CMAKE_BINARY_DIR}/app.a ttls Threads::Threads mbedtls mbedx509 mbedcrypto)

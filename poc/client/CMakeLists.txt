# Copyright (c) Edgeless Systems GmbH.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)
project(sample)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif ()

add_custom_target(
  app ertgo build -buildmode=c-archive ${CMAKE_SOURCE_DIR}/app)

add_executable(client main.c)
add_dependencies(client app)

target_link_libraries(client Threads::Threads ${CMAKE_BINARY_DIR}/app.a)

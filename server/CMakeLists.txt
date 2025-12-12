cmake_minimum_required(VERSION 3.14)
project(server)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(server src/server.cpp)
target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

cmake_minimum_required(VERSION 3.10)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(z-stack)

add_compile_options(-fsanitize=address)
add_link_options(-fsanitize=address)

find_package(PkgConfig REQUIRED)

pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)

add_library(z-stack lib/config.c lib/api.c lib/dpdk.c lib/ip.c  lib/tcp.c lib/arp.c )

target_include_directories(z-stack PUBLIC include lib)

target_link_libraries(z-stack PRIVATE PkgConfig::DPDK)


add_executable(tcp_server examples/tcp_server/main.c examples/tcp_server/server.c)  

target_link_libraries(tcp_server PRIVATE PkgConfig::DPDK z-stack)

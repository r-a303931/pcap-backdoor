cmake_minimum_required(VERSION 3.7)
project(c2target VERSION 1.0.0 LANGUAGES C)

include(FindPkgConfig)
pkg_search_module(PCAP REQUIRED libpcap)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

pkg_search_module(BSD REQUIRED libbsd)

include_directories(${PCAP_INCLUDE_DIRS})
add_executable(c2target src/main.c)
target_link_libraries(c2target ${PCAP_LIBRARIES} ${BSD_LIBRARIES} Threads::Threads)

target_compile_options(c2target PRIVATE -Werror -Wall -Wpedantic)

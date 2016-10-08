cmake_minimum_required(VERSION 2.8.3)
project(vdnsd)
FIND_PACKAGE ( Threads REQUIRED )

find_library(LIBEV_LIBRARY NAMES ev)
find_path(LIBEV_INCLUDE_DIR ev.h
        PATH_SUFFIXES include/ev include
        ) # Find header
find_package_handle_standard_args(libev DEFAULT_MSG LIBEV_LIBRARY LIBEV_INCLUDE_DIR)
set(CMAKE_BUILD_TYPE Debug)
add_definitions( "-D_DEBUG" )
#add_definitions( "-std=c99" )
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall")
#add_subdirectory(src/udns)

add_executable(vdnsd src/main.c src/dns.c src/thpool.c src/dnsworker.c src/redis.c src/dns_cache.c src/import.c src/config.c src/logger.c src/pid.c src/pid.h src/qps_counter.c src/qps_counter.h)


#target_link_libraries(vdns udns)
target_link_libraries(vdnsd ev)
target_link_libraries(vdnsd pthread)
target_link_libraries(vdnsd eredis)
target_link_libraries(vdnsd resolv)

install(TARGETS vdnsd DESTINATION bin COMPONENT binaries)
install(FILES vdnsd.conf.example DESTINATION etc/vdnsd COMPONENT config)
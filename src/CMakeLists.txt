cmake_minimum_required(VERSION 3.0)

include(GNUInstallDirs)

project(Radio_service_client)

set(VSOMEIP_NAME "vsomeip3")

set(CMAKE_CXX_FLAGS "-g -std=c++0x")

# vsomeip_DIR should be set by find_package or provided if not in standard path
# find_package(vsomeip3 REQUIRED)

include_directories(${VSOMEIP_INCLUDE_DIRS})

find_package(Boost COMPONENTS system thread log REQUIRED)

find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add the UNICAST_ADDRESS and UNICAST_PORT as user-specified options
option(UNICAST_ADDRESS "Set the unicast address" "172.20.0.101")
option(UNICAST_PORT "Set the unicast port" 12345)

add_definitions(
    -DUNICAST_ADDRESS=${UNICAST_ADDRESS}
    -DUNICAST_PORT=${UNICAST_PORT}
)

add_executable(radio_service
    radio-service.cpp
    services.hpp
    radio-stations.cpp)

target_link_libraries(radio_service vsomeip3 ${Boost_LIBRARIES} Threads::Threads)

add_executable(radio_client
    radio-client.cpp
    services.hpp)

target_link_libraries(radio_client vsomeip3 ${Boost_LIBRARIES} Threads::Threads)

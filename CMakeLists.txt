cmake_minimum_required(VERSION 3.15)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_TOOLCHAIN_FILE /home/kleeper/vcpkg/scripts/buildsystems/vcpkg.cmake)

project(TinyShark)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
file(GLOB SRC_LIST ${PROJECT_SOURCE_DIR}/src/*.cpp)
add_executable(TinyShark ${SRC_LIST})

include_directories(${PROJECT_SOURCE_DIR}/include)
find_package(PcapPlusPlus CONFIG REQUIRED)
target_link_libraries(TinyShark PcapPlusPlus::Pcap++ PcapPlusPlus::Packet++ PcapPlusPlus::Common++ pthread)
cmake_minimum_required(VERSION 3.9)
project(doryponyapps CXX)

include(${CMAKE_BINARY_DIR}/setup.cmake)
dory_setup_cmake()

string(TIMESTAMP BUILD_TIME "%Y-%m-%d %H:%M")
add_definitions(-DBINARY_BUILD_TIME="${BUILD_TIME}")

add_executable(audit-client ${HEADER_TIDER} auditable/client.cpp)
target_link_libraries(audit-client ${CONAN_LIBS})

add_executable(audit-server ${HEADER_TIDER} auditable/server.cpp)
target_link_libraries(audit-server ${CONAN_LIBS})

# add_executable(ponydemo ${HEADER_TIDER} main.cpp)
# target_link_libraries(ponydemo ${CONAN_LIBS})

# add_executable(pony-ping ${HEADER_TIDER} ping.cpp)
# target_link_libraries(pony-ping ${CONAN_LIBS})

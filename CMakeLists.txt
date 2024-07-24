cmake_minimum_required (VERSION 3.10)

project (pr-oprf)
set(NAME "pr-oprf")

# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

find_package(emp-ot REQUIRED)
find_package(GMP REQUIRED)
include_directories(
  ${EMP-OT_INCLUDE_DIRS}
  ${GMP_INCLUDE_DIR}
  ${GMPXX_INCLUDE_DIR}
)
set(sources
  emp-zk/emp-zk-bool/emp-zk-bool.cpp
  emp-zk/emp-zk-arith/emp-zk-arith.cpp
)
add_library(${NAME} SHARED ${sources})

install(DIRECTORY emp-zk DESTINATION include/)
install(FILES cmake/emp-zk-config.cmake DESTINATION cmake/)
install(TARGETS ${NAME} DESTINATION lib)

enable_testing()
add_subdirectory(test)

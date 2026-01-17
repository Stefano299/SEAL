cmake_minimum_required(VERSION 3.13)
project(SEALProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SEAL 4.1.2 CONFIG REQUIRED)

add_executable(SEALProject
    main.cpp message.cpp packet_assembler.cpp
)

target_include_directories(SEALProject PRIVATE incs)
target_link_libraries(SEALProject PRIVATE SEAL::seal)

add_compile_options(
  -Wall -Wextra -Werror -pedantic
  -O3 -march=native
)
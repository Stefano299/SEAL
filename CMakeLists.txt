cmake_minimum_required(VERSION 3.13)
project(SEALProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SEAL 4.1.2 CONFIG REQUIRED)

# Sender (da eseguire in nsp0)
add_executable(sender
    sender.cpp message.cpp packet_assembler.cpp
)
target_include_directories(sender PRIVATE incs)
target_link_libraries(sender PRIVATE SEAL::seal)

# Receiver (da eseguire in nsp1)
add_executable(receiver
    receiver.cpp packet_assembler.cpp
)
target_include_directories(receiver PRIVATE incs)
target_link_libraries(receiver PRIVATE SEAL::seal)

# Keygen (eseguire una volta sola prima di receiver e sender)
add_executable(keygen
    keygen.cpp
)
target_include_directories(keygen PRIVATE incs)
target_link_libraries(keygen PRIVATE SEAL::seal)

add_compile_options(
  -Wall -Wextra -Werror -pedantic
  -O3 -march=native
)
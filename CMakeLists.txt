cmake_minimum_required(VERSION 3.16)

project(crypto-main VERSION 1.0.0 LANGUAGES CXX)

# Global C++ standard settings
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for all subprojects
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Fetch Catch2 once for all subprojects
include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG v3.8.0
)
FetchContent_MakeAvailable(Catch2)

# Enable testing with CTest
include(CTest)
enable_testing()

# Add subprojects
add_subdirectory(cryptography)
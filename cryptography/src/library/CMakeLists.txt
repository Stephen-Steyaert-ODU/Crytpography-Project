file(GLOB_RECURSE LIB_SOURCES
    CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

add_library(library)

target_sources(library PRIVATE ${LIB_SOURCES})

find_package(OpenSSL REQUIRED)
find_library(GMP_LIB NAMES gmp REQUIRED)
find_library(GMPXX_LIB NAMES gmpxx REQUIRED)
find_path(GMP_INCLUDE_DIR NAMES gmpxx.h REQUIRED)

target_include_directories(library PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${GMP_INCLUDE_DIR}
)

target_link_libraries(library PUBLIC
    OpenSSL::Crypto
    ${GMP_LIB}
    ${GMPXX_LIB}
)

target_compile_features(library PUBLIC cxx_std_20)

target_precompile_headers(library PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/common/common.hpp)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(library PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_library(cryptography::library ALIAS library)
file(GLOB_RECURSE LIB_SOURCES
    CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

add_library(library)

target_sources(library PRIVATE ${LIB_SOURCES})

target_include_directories(library PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(library PUBLIC cxx_std_20)

target_precompile_headers(library PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/common/common.hpp)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    target_compile_options(library PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_library(template::library ALIAS library)
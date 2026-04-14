include(CTest)

file(GLOB_RECURSE TEST_SOURCES
    CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

add_executable(cryptography_tests)

target_sources(
    cryptography_tests
    PRIVATE
    ${TEST_SOURCES}
)

target_link_libraries(cryptography_tests
    PRIVATE cryptography::library Catch2::Catch2WithMain
)

target_compile_features(cryptography_tests PRIVATE cxx_std_20)

include(Catch)

catch_discover_tests(cryptography_tests)
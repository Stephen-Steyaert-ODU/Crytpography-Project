include(CTest)

file(GLOB_RECURSE TEST_SOURCES
    CONFIGURE_DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
)

add_executable(template_tests)

target_sources(
    template_tests
    PRIVATE
    ${TEST_SOURCES}
)

target_link_libraries(template_tests
    PRIVATE template::library Catch2::Catch2WithMain
)

target_compile_features(template_tests PRIVATE cxx_std_20)

include(Catch)

catch_discover_tests(template_tests)
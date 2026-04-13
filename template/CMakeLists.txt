project(template-subproject VERSION 0.1.0 LANGUAGES CXX)

# Set executable output directory for this project
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# Add subdirectories
add_subdirectory(src/library)
add_subdirectory(src/executable)
add_subdirectory(tests)
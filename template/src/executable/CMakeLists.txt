add_executable(template)

target_sources(
    template
    PRIVATE
    main.cpp
)

target_link_libraries(
    template
    PRIVATE 
    template::library
)

target_compile_features(template PRIVATE cxx_std_20)
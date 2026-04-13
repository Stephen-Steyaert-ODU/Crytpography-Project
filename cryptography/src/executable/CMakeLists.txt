add_executable(cryptography)

target_sources(
    cryptography
    PRIVATE
    main.cpp
)

target_link_libraries(
    cryptography
    PRIVATE 
    cryptography::library
)

target_compile_features(cryptography PRIVATE cxx_std_20)
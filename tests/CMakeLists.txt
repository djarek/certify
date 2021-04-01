function (certify_verify_add_test test_file)
    get_filename_component(target_name ${test_file} NAME_WE)
    add_executable(${target_name} ${test_file})
    target_link_libraries(${target_name} certify::core)
    target_include_directories(${target_name} PRIVATE ../include ../tests/extras/include)
    if ( CMAKE_COMPILER_IS_GNUCC )
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -pedantic)
    endif()

    add_test(NAME "${target_name}_tests"
             COMMAND ${target_name})
endfunction(certify_verify_add_test)

certify_verify_add_test(extensions.cpp)
certify_verify_add_test(https_verification_success.cpp)
certify_verify_add_test(https_verification_fail.cpp)
certify_verify_add_test(crl_set_parser.cpp)
certify_verify_add_test(detail_spki_digest.cpp)
certify_verify_add_test(status_cache.cpp)

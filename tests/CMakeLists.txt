function (certify_verify_add_test test_file)
    get_filename_component(target_name ${test_file} NAME_WE)
    add_executable(${target_name} ${test_file})
    target_link_libraries(${target_name} certify::core Boost::unit_test_framework)
    if ( CMAKE_COMPILER_IS_GNUCC )
        target_compile_options(${target_name} PRIVATE -Wall -Wextra -pedantic)
    endif()
    target_compile_definitions(${target_name} PRIVATE BOOST_TEST_DYN_LINK BOOST_TEST_MODULE="${target_name}")

    add_test(NAME "${target_name}_tests"
             COMMAND ${target_name})
endfunction(certify_verify_add_test)

certify_verify_add_test(rfc2818_verification.cpp)

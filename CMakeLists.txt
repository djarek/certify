cmake_minimum_required(VERSION 3.8)
project(tlsverify VERSION 0.1 LANGUAGES CXX)

list(INSERT CMAKE_MODULE_PATH 0 ${PROJECT_SOURCE_DIR}/CMakeModules)

if (CMAKE_VERSION VERSION_LESS 3.11)
    # Latest FindBoost.cmake has likely been updated to detect Boost version not yet released
    if (NOT EXISTS "${CMAKE_BINARY_DIR}/cmake/FindBoost.cmake")
        message(STATUS "Downloading FindBoost.cmake from https://gitlab.kitware.com/cmake/ release branch")
        file(
            DOWNLOAD
            "https://gitlab.kitware.com/cmake/cmake/raw/release/Modules/FindBoost.cmake"
            "${CMAKE_BINARY_DIR}/cmake/FindBoost.cmake")
    endif()
    list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_BINARY_DIR}/cmake)
endif()

find_package(Boost 1.67
             COMPONENTS
                system
                unit_test_framework
             REQUIRED)

find_package (Threads)

find_package(OpenSSL REQUIRED)


add_library(tls INTERFACE)

add_library(tlsverify::tls ALIAS tls)

target_compile_features(tls INTERFACE cxx_std_11)

target_include_directories(tls INTERFACE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(
    tls
    INTERFACE
        Boost::system
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto)

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "tlsverifyConfigVersion.cmake"
    COMPATIBILITY AnyNewerVersion)

install(FILES
            "tlsverifyConfig.cmake"
            "${CMAKE_BINARY_DIR}/tlsverifyConfigVersion.cmake"
        DESTINATION lib/cmake/tlsverify)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/
        DESTINATION include
        FILES_MATCHING PATTERN "*.hpp")

install(TARGETS tls
        EXPORT tlsverifyTargets
        INCLUDES DESTINATION include)

install(EXPORT tlsverifyTargets
        FILE tlsverifyTargets.cmake
        NAMESPACE tlsverify::
        DESTINATION lib/cmake/tlsverify)

include(CTest)
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

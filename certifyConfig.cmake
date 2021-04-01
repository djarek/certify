include(CMakeFindDependencyMacro)

find_dependency(Boost COMPONENTS system)
find_dependency(Threads)

include("${CMAKE_CURRENT_LIST_DIR}/certifyTargets.cmake")

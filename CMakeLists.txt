cmake_minimum_required(VERSION 3.15)
project(Illu)
find_package(CBuildKit REQUIRED)

option(USE_STATIC_LINKING "Use static linking for the runtime" ON)

if (USE_STATIC_LINKING)
    if (MSVC)
        # MSVC specific static linking flag
        add_compile_options(/MT$<$<CONFIG:Debug>:d>)
    else()
        # GCC/Clang specific static linking flag
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    endif()
endif()

include_directories(include)
add_subdirectory(src)
add_subdirectory(playg)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION include)

install_cfgpkg(illu
"
include(CMakeFindDependencyMacro)
find_dependency(UcPP)
find_dependency(simplistic-io)
include(\${CMAKE_CURRENT_LIST_DIR}/illu-illu-targets.cmake)
")
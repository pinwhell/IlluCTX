find_package(simplistic-io REQUIRED)
find_package(UcPP REQUIRED)
file(GLOB ILLUCTX_SRCS *.cpp)
add_library_ns(illu illu STATIC ${ILLUCTX_SRCS})
target_link_libraries(illu-illu
ucpp::ucpp
simplistic::io
)
install_target_and_headers(illu illu)
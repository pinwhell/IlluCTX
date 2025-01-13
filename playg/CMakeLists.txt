find_package(simplistic-proc)
if(simplistic-proc_FOUND)
find_package(CStone)
if(CStone_FOUND)
add_compile_definitions(-DHAS_CSTONE)
endif()
add_executable(playg playg.cpp)
target_link_libraries(playg
simplistic::proc
illu::illu
)
if(CStone_FOUND)
target_link_libraries(playg cstone::cstone)
endif()
endif()


cmake_minimum_required(VERSION 3.20)
project(ttexplore)

find_package(triton REQUIRED CONFIG)
find_package(LIEF REQUIRED CONFIG)
link_libraries(${TRITON_LIBRARIES})
link_libraries(${LIEF_LIBRARIES})

include_directories(${TRITON_INCLUDE_DIRS})
include_directories(${LIEF_INCLUDE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/lib)

add_library(ttexplore STATIC
    lib/ttexplore.cpp
    lib/routines.cpp
)

add_executable(harness1
    harness/1/harness.cpp
)

add_executable(harness2
    harness/2/harness.cpp
)

add_executable(harness3
    harness/3/harness.cpp
)

add_executable(harness4
    harness/4/harness.cpp
)

add_executable(harness5
    harness/5/harness.cpp
)

add_executable(harness6
    harness/6/harness.cpp
)

target_link_libraries(harness1 ttexplore)
target_link_libraries(harness2 ttexplore)
target_link_libraries(harness3 ttexplore)
target_link_libraries(harness4 ttexplore)
target_link_libraries(harness5 ttexplore)
target_link_libraries(harness6 ttexplore)

target_compile_options(ttexplore PRIVATE -std=c++14)
target_compile_options(harness1 PRIVATE -std=c++14)
target_compile_options(harness2 PRIVATE -std=c++14)
target_compile_options(harness3 PRIVATE -std=c++14)
target_compile_options(harness4 PRIVATE -std=c++14)
target_compile_options(harness5 PRIVATE -std=c++14)
target_compile_options(harness6 PRIVATE -std=c++14)

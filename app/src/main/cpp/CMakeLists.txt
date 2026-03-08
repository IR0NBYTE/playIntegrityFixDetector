cmake_minimum_required(VERSION 3.22.1)

project("playIntegrityFixDetector")

add_library(${CMAKE_PROJECT_NAME} SHARED native-lib.cpp)

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
        -fvisibility=hidden
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2)

target_link_options(${CMAKE_PROJECT_NAME} PRIVATE
        -Wl,--strip-all
        -Wl,-z,relro
        -Wl,-z,now)

target_link_libraries(${CMAKE_PROJECT_NAME} android log)

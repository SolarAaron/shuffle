cmake_minimum_required (VERSION 3.12)
project(shuffle VERSION 0.1)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if (WIN32)
    option(BUILD_STATIC_LIBS "Build the static library" ON)
    option(BUILD_SHARED_LIBS "Build the shared library" OFF)
else ()
    option(BUILD_STATIC_LIBS "Build the static library" ON)
    option(BUILD_SHARED_LIBS "Build the shared library" ON)
endif ()
include_directories("${PROJECT_SOURCE_DIR}/include")

install(FILES include/crypto_c.h include/slr.crypto.hpp DESTINATION include)

set(CMAKE_BINARY_DIR ${CMAKE_BINARY_DIR}/build)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

list(APPEND PRIMES 2 3 5 7 11 13)

foreach(PRIME ${PRIMES})
    foreach(VAR ${VARIANTS})
        string(REPLACE "_" ";" VARL ${VAR})
        string(REPLACE "_" "*" VARM ${VAR})
        math(EXPR MV "${VARM} * ${PRIME}")
        if(${MV} LESS 16384)
            set(CVL ${PRIME} ${VARL})
            list(SORT CVL ORDER DESCENDING COMPARE NATURAL)
            string(REPLACE ";" "_" CV "${CVL}")
            list(APPEND VARIANTS ${CV})
            list(APPEND VARIANTS ${MV})
        endif ()
    endforeach()

    list(APPEND VARIANTS ${PRIME})
endforeach()

list(REMOVE_DUPLICATES VARIANTS)
list(SORT VARIANTS ORDER DESCENDING COMPARE NATURAL)

set(BLOCK_SIZES 8 16 32 64 128 256)

add_subdirectory(hash)
add_subdirectory(encrypt)

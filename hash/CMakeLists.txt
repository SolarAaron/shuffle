# SPDX-FileCopyrightText: 2024-2026 Aaron Torres
# SPDX-License-Identifier: MIT

add_library(slrcrypto_c crypto.cxx)
set_property(TARGET slrcrypto_c PROPERTY WINDOWS_EXPORT_ALL_SYMBOLS ON)
install(TARGETS slrcrypto_c)
get_property(SLRCRYPTO_API_OBJECT_TARGETS GLOBAL PROPERTY SLRCRYPTO_API_OBJECT_TARGETS)
foreach(API_OBJECT_TARGET ${SLRCRYPTO_API_OBJECT_TARGETS})
    target_link_libraries(slrcrypto_c ${API_OBJECT_TARGET})
endforeach()

foreach(VARIANT ${VARIANTS})
    string(REPLACE _ , V_HASH ${VARIANT})

    add_library(hash_def_${VARIANT} OBJECT crypto_any.cxx)
    target_compile_definitions(hash_def_${VARIANT} PRIVATE HASH_SIGNATURE=${VARIANT} HASH_DEFINITION=${V_HASH})
    set_property(TARGET hash_def_${VARIANT} PROPERTY POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(slrcrypto_c hash_def_${VARIANT})

    add_executable(poker-${VARIANT} main_any.cxx)
    install(TARGETS poker-${VARIANT})
    target_compile_definitions(poker-${VARIANT} PUBLIC HASH_SIGNATURE=${VARIANT})
    target_link_libraries(poker-${VARIANT} slrcrypto_c)

    add_executable(poker64-${VARIANT} main64_any.cxx)
    install(TARGETS poker64-${VARIANT})
    target_compile_definitions(poker64-${VARIANT} PUBLIC HASH_SIGNATURE=${VARIANT})
    target_link_libraries(poker64-${VARIANT} slrcrypto_c)

    foreach (TRUNCATION_MULTIPLIER ${TRUNCATION_MULTIPLIERS})
        string(REPLACE "_" "*" VARM ${VARIANT})
        math(EXPR TV "${VARM} * ${VARM} * ${TRUNCATION_MULTIPLIER}")

        add_library(hash_def_T${TV}_${VARIANT} OBJECT crypto_ct_any.cxx)
        target_compile_definitions(hash_def_T${TV}_${VARIANT} PRIVATE HASH_SIGNATURE=${VARIANT} HASH_DEFINITION=${V_HASH} TRUNCATION=${TV})
        set_property(TARGET hash_def_T${TV}_${VARIANT} PROPERTY POSITION_INDEPENDENT_CODE ON)
        target_link_libraries(slrcrypto_c hash_def_T${TV}_${VARIANT})

        add_executable(poker-T${TV}_${VARIANT} main_t_any.cxx)
        install(TARGETS poker-T${TV}_${VARIANT})
        target_compile_definitions(poker-T${TV}_${VARIANT} PUBLIC HASH_SIGNATURE=${VARIANT} TRUNCATION=${TV})
        target_link_libraries(poker-T${TV}_${VARIANT} slrcrypto_c)

        add_executable(poker64-T${TV}_${VARIANT} main64_t_any.cxx)
        install(TARGETS poker64-T${TV}_${VARIANT})
        target_compile_definitions(poker64-T${TV}_${VARIANT} PUBLIC HASH_SIGNATURE=${VARIANT} TRUNCATION=${TV})
        target_link_libraries(poker64-T${TV}_${VARIANT} slrcrypto_c)
    endforeach ()

    foreach(BSIZE ${BLOCK_SIZES})
        string(CONCAT V_NAME ${BSIZE} _ ${VARIANT})
        string(REPLACE _ , V_SPEC ${V_NAME})

        add_executable(hmac-${V_NAME} main_hmac_any.cxx)
        target_compile_definitions(hmac-${V_NAME} PUBLIC MAC_DEFINITION=${V_SPEC})

        add_executable(pbk-${V_NAME} main_pbk_any.cxx)
        target_compile_definitions(pbk-${V_NAME} PUBLIC MAC_DEFINITION=${V_SPEC})
    endforeach()
endforeach()

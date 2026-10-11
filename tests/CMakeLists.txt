# SPDX-FileCopyrightText: 2024-2026 Aaron Torres
# SPDX-License-Identifier: MIT

list(GET VARIANTS 0 C_API_VARIANT)

add_executable(test-c-api c_api.c)
target_compile_definitions(test-c-api PRIVATE
    HASH_SIGNATURE=${C_API_VARIANT}
    BLOCK_SIZE=8
)
if (TRUNCATION_MULTIPLIERS)
    list(GET TRUNCATION_MULTIPLIERS 0 C_API_TRUNCATION_MULTIPLIER)
    string(REPLACE "_" "*" C_API_VARIANT_PRODUCT ${C_API_VARIANT})
    math(EXPR C_API_TRUNCATION
        "${C_API_VARIANT_PRODUCT} * ${C_API_VARIANT_PRODUCT} * ${C_API_TRUNCATION_MULTIPLIER}")
    target_compile_definitions(test-c-api PRIVATE TRUNCATION=${C_API_TRUNCATION})
endif ()
target_link_libraries(test-c-api PRIVATE slrcrypto_c)
set_property(TARGET test-c-api PROPERTY LINKER_LANGUAGE CXX)

add_test(NAME c-api COMMAND test-c-api)
set_tests_properties(c-api PROPERTIES LABELS "c-api" TIMEOUT 120)

add_executable(test-shuffle-context shuffle_context.cxx)
add_test(NAME shuffle-context COMMAND test-shuffle-context)
set_tests_properties(shuffle-context PROPERTIES LABELS "crypto" TIMEOUT 120)

add_executable(test-crypto-optimizations crypto_optimizations.cxx)
add_test(NAME crypto-optimizations COMMAND test-crypto-optimizations)
set_tests_properties(crypto-optimizations PROPERTIES LABELS "crypto" TIMEOUT 120)

add_executable(test-cipher-vectors cipher_vectors.cxx)
add_test(NAME cipher-vectors COMMAND test-cipher-vectors)
set_tests_properties(cipher-vectors PROPERTIES LABELS "crypto" TIMEOUT 120)

add_executable(test-file-format file_format.cxx)
target_include_directories(test-file-format PRIVATE ${PROJECT_SOURCE_DIR}/encrypt)
add_test(NAME file-format COMMAND test-file-format)
set_tests_properties(file-format PROPERTIES LABELS "crypto" TIMEOUT 120)

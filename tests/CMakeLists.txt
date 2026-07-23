# SPDX-FileCopyrightText: 2024-2026 Aaron Torres
# SPDX-License-Identifier: MIT

foreach(VARIANT ${VARIANTS})
    string(REPLACE "_" "," TEST_DEFINITION "${VARIANT}")
    string(REPLACE "_" "*" TEST_PRODUCT "${VARIANT}")
    math(EXPR TEST_BITS "8 * ${TEST_PRODUCT} * ${TEST_PRODUCT}")

    add_executable(test-variant-${VARIANT} variant.cxx)
    target_compile_definitions(test-variant-${VARIANT} PRIVATE
        HASH_DEFINITION=${TEST_DEFINITION}
        HASH_SIGNATURE=${VARIANT}
        EXPECTED_BITS=${TEST_BITS}
        VARIANT_NAME="${VARIANT}"
    )
    target_link_libraries(test-variant-${VARIANT} PRIVATE slrcrypto_c)

    add_test(NAME variant-${VARIANT} COMMAND test-variant-${VARIANT})
    set_tests_properties(variant-${VARIANT} PROPERTIES
        LABELS "variant"
        TIMEOUT 120
    )

    foreach(TRUNCATION_MULTIPLIER ${TRUNCATION_MULTIPLIERS})
        math(EXPR TEST_TRUNCATION "${TEST_PRODUCT} * ${TEST_PRODUCT} * ${TRUNCATION_MULTIPLIER}")
        add_executable(test-truncated-${TEST_TRUNCATION}-${VARIANT} truncated.cxx)
        target_compile_definitions(test-truncated-${TEST_TRUNCATION}-${VARIANT} PRIVATE
            HASH_DEFINITION=${TEST_DEFINITION}
            HASH_SIGNATURE=${VARIANT}
            TRUNCATION=${TEST_TRUNCATION}
            VARIANT_NAME="${VARIANT}"
        )
        target_link_libraries(test-truncated-${TEST_TRUNCATION}-${VARIANT} PRIVATE slrcrypto_c)

        add_test(NAME truncated-${TEST_TRUNCATION}-${VARIANT}
                 COMMAND test-truncated-${TEST_TRUNCATION}-${VARIANT})
        set_tests_properties(truncated-${TEST_TRUNCATION}-${VARIANT} PROPERTIES
            LABELS "truncated;variant"
            TIMEOUT 120
        )
    endforeach()
endforeach()

# Compile the public headers as C and exercise one generated full/truncated API pair.
list(GET VARIANTS -1 C_API_VARIANT)
set(C_API_COMPILE_DEFINITIONS HASH_SIGNATURE=${C_API_VARIANT} BLOCK_SIZE=8)
if(TRUNCATION_MULTIPLIERS)
    list(GET TRUNCATION_MULTIPLIERS 0 C_API_TRUNCATION_MULTIPLIER)
    string(REPLACE "_" "*" C_API_PRODUCT "${C_API_VARIANT}")
    math(EXPR C_API_TRUNCATION
        "${C_API_PRODUCT} * ${C_API_PRODUCT} * ${C_API_TRUNCATION_MULTIPLIER}")
    list(APPEND C_API_COMPILE_DEFINITIONS TRUNCATION=${C_API_TRUNCATION})
endif()

add_executable(test-c-api c_api.c)
target_compile_definitions(test-c-api PRIVATE ${C_API_COMPILE_DEFINITIONS})
target_link_libraries(test-c-api PRIVATE slrcrypto_c)
set_property(TARGET test-c-api PROPERTY LINKER_LANGUAGE CXX)
add_test(NAME c-api COMMAND test-c-api)
set_tests_properties(c-api PROPERTIES LABELS "c-api" TIMEOUT 120)

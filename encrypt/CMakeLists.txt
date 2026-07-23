# SPDX-FileCopyrightText: 2024-2026 Aaron Torres
# SPDX-License-Identifier: MIT

foreach(VARIANT ${VARIANTS})
    string(REPLACE _ , V_HASH ${VARIANT})
    string(REPLACE _ "*" V_PRODUCT ${VARIANT})
    foreach(BSIZE ${BLOCK_SIZES})
        string(CONCAT V_NAME ${BSIZE} _ ${VARIANT})
        string(REPLACE _ , V_SPEC ${V_NAME})

        add_executable(shuffle-${V_NAME} main_enc_any.cxx args.cxx terminal_password.cxx)
        install(TARGETS shuffle-${V_NAME})
        target_compile_definitions(shuffle-${V_NAME} PUBLIC BLOCK_SIZE=${BSIZE} CIPHER_DEFINITION=${V_SPEC} CIPHER_NAME=\"${V_NAME}\" HASH_DEFINITION=${V_HASH})

        add_executable(deshuffle-${V_NAME} main_dec_any.cxx args.cxx terminal_password.cxx)
        install(TARGETS deshuffle-${V_NAME})
        target_compile_definitions(deshuffle-${V_NAME} PUBLIC BLOCK_SIZE=${BSIZE} CIPHER_DEFINITION=${V_SPEC} CIPHER_NAME=\"${V_NAME}\" HASH_DEFINITION=${V_HASH})

        add_library(crypto_api_${V_NAME} OBJECT crypto_api_any.cxx)
        target_compile_definitions(crypto_api_${V_NAME} PRIVATE
            BLOCK_SIZE=${BSIZE}
            HASH_SIGNATURE=${VARIANT}
            HASH_DEFINITION=${V_HASH}
        )
        set_property(TARGET crypto_api_${V_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
        set_property(GLOBAL APPEND PROPERTY SLRCRYPTO_API_OBJECT_TARGETS crypto_api_${V_NAME})

        foreach(TRUNCATION_MULTIPLIER ${TRUNCATION_MULTIPLIERS})
            math(EXPR TRUNCATION_BITS "${V_PRODUCT} * ${V_PRODUCT} * ${TRUNCATION_MULTIPLIER}")
            string(CONCAT T_NAME T${TRUNCATION_BITS} _ ${V_NAME})

            add_executable(shuffle-${T_NAME} main_enc_any.cxx args.cxx terminal_password.cxx)
            install(TARGETS shuffle-${T_NAME})
            target_compile_definitions(shuffle-${T_NAME} PUBLIC
                BLOCK_SIZE=${BSIZE}
                CIPHER_NAME=\"${T_NAME}\"
                HASH_DEFINITION=${V_HASH}
                TRUNCATION=${TRUNCATION_BITS}
            )

            add_executable(deshuffle-${T_NAME} main_dec_any.cxx args.cxx terminal_password.cxx)
            install(TARGETS deshuffle-${T_NAME})
            target_compile_definitions(deshuffle-${T_NAME} PUBLIC
                BLOCK_SIZE=${BSIZE}
                CIPHER_NAME=\"${T_NAME}\"
                HASH_DEFINITION=${V_HASH}
                TRUNCATION=${TRUNCATION_BITS}
            )

            add_library(crypto_api_${T_NAME} OBJECT crypto_api_any.cxx)
            target_compile_definitions(crypto_api_${T_NAME} PRIVATE
                BLOCK_SIZE=${BSIZE}
                HASH_SIGNATURE=${VARIANT}
                HASH_DEFINITION=${V_HASH}
                TRUNCATION=${TRUNCATION_BITS}
            )
            set_property(TARGET crypto_api_${T_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)
            set_property(GLOBAL APPEND PROPERTY SLRCRYPTO_API_OBJECT_TARGETS crypto_api_${T_NAME})
        endforeach()
    endforeach ()
endforeach ()

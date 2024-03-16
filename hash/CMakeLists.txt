add_library(slrcrypto_c crypto.cxx)
install(TARGETS slrcrypto_c)

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

    foreach(BSIZE ${BLOCK_SIZES})
        string(CONCAT V_NAME ${BSIZE} _ ${VARIANT})
        string(REPLACE _ , V_SPEC ${V_NAME})

        add_executable(hmac-${V_NAME} main_hmac_any.cxx)
        target_compile_definitions(hmac-${V_NAME} PUBLIC MAC_DEFINITION=${V_SPEC})

        add_executable(pbk-${V_NAME} main_pbk_any.cxx)
        target_compile_definitions(pbk-${V_NAME} PUBLIC MAC_DEFINITION=${V_SPEC})
    endforeach()
endforeach()

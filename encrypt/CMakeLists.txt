foreach(VARIANT ${VARIANTS})
    foreach(BSIZE ${BLOCK_SIZES})
        string(CONCAT V_NAME ${BSIZE} _ ${VARIANT})
        string(REPLACE _ , V_SPEC ${V_NAME})

        add_executable(shuffle-${V_NAME} main_enc_any.cxx args.cxx)
        target_compile_definitions(shuffle-${V_NAME} PUBLIC BLOCK_SIZE=${BSIZE})
        target_compile_definitions(shuffle-${V_NAME} PUBLIC CIPHER_DEFINITION=${V_SPEC})

        add_executable(deshuffle-${V_NAME} main_dec_any.cxx args.cxx)
        target_compile_definitions(deshuffle-${V_NAME} PUBLIC BLOCK_SIZE=${BSIZE})
        target_compile_definitions(deshuffle-${V_NAME} PUBLIC CIPHER_DEFINITION=${V_SPEC})
    endforeach ()
endforeach ()

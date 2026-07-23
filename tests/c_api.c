// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "crypto_ct.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    static const char key[] = "c-api-key";
    static const char salt[BLOCK_SIZE] = {0};
    static const char input[BLOCK_SIZE] = "c-api";
    uint8_t encrypted[BLOCK_SIZE];
    uint8_t decrypted[BLOCK_SIZE];
    uint8_t derived[16];

    const size_t digest_size = get_hmac_size(BLOCK_SIZE, HASH_SIGNATURE)();
    uint8_t *digest = (uint8_t *) malloc(digest_size);
    if(get_default_shuffle_iterations(HASH_SIGNATURE)() == 0 ||
       !digest || hmac(BLOCK_SIZE, HASH_SIGNATURE)(sizeof(key) - 1, key,
            sizeof(input), input, digest, digest_size) != 0 ||
       pbkdf2(BLOCK_SIZE, HASH_SIGNATURE)(sizeof(key) - 1, key, sizeof(salt), salt,
            1, derived, sizeof(derived)) != 0 ||
       shuffle_encrypt(BLOCK_SIZE, HASH_SIGNATURE)(sizeof(key) - 1, key,
            sizeof(salt), salt, sizeof(input), input, 1, encrypted, sizeof(encrypted)) != 0 ||
       shuffle_decrypt(BLOCK_SIZE, HASH_SIGNATURE)(sizeof(key) - 1, key,
            sizeof(salt), salt, sizeof(encrypted), (const char *) encrypted, 1,
            decrypted, sizeof(decrypted)) != 0 ||
       memcmp(input, decrypted, sizeof(input)) != 0) {
        free(digest);
        return 1;
    }
    free(digest);

#ifdef TRUNCATION
    const size_t truncated_size =
        get_hmac_size_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)();
    uint8_t *truncated = (uint8_t *) malloc(truncated_size);
    if(!truncated || hmac_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)(
            sizeof(key) - 1, key, sizeof(input), input, truncated, truncated_size) != 0 ||
       pbkdf2_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)(
            sizeof(key) - 1, key, sizeof(salt), salt, 1, derived, sizeof(derived)) != 0 ||
       shuffle_encrypt_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)(
            sizeof(key) - 1, key, sizeof(salt), salt, sizeof(input), input, 1,
            encrypted, sizeof(encrypted)) != 0 ||
       shuffle_decrypt_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)(
            sizeof(key) - 1, key, sizeof(salt), salt, sizeof(encrypted),
            (const char *) encrypted, 1, decrypted, sizeof(decrypted)) != 0 ||
       memcmp(input, decrypted, sizeof(input)) != 0) {
        free(truncated);
        return 1;
    }
    free(truncated);
#endif

    return 0;
}

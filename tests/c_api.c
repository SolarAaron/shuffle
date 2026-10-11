// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "crypto_ct.h"

#include <stdlib.h>
#include <string.h>

static const char message[] = "C API incremental hash test";

static struct poker_hash_sum const *new_hash(void) {
    struct poker_hash_sum const *hash = init_poker_hash(HASH_SIGNATURE)();
    if(hash == NULL || hash_block(HASH_SIGNATURE)(hash, message, 8, 0) != 0 ||
       hash_block(HASH_SIGNATURE)(hash, message, sizeof(message) - 1 - 8, 8) != 0) {
        return NULL;
    }
    return hash;
}

static int check_full_digest(int base64) {
    struct poker_hash_sum const *hash = new_hash();
    if(hash == NULL) return 1;

    const size_t required = base64
        ? get_hash64_size(HASH_SIGNATURE)(hash)
        : get_hash_size(HASH_SIGNATURE)(hash);
    char *destination = (char *) calloc(required, sizeof(char));
    if(destination == NULL) return 1;

    const int result = base64
        ? finish_hash64(HASH_SIGNATURE)(hash, destination, 0)
        : finish_hash(HASH_SIGNATURE)(hash, destination, 0);
    const int invalid = result != 0 || required == 0 || strlen(destination) != required - 1;
    free(destination);
    return invalid;
}

#ifdef TRUNCATION
static int check_truncated_digest(int base64) {
    struct poker_hash_sum const *hash = new_hash();
    if(hash == NULL) return 1;

    const size_t required = base64
        ? ((TRUNCATION + 5u) / 6u) + 1u
        : (((TRUNCATION + 7u) / 8u) * 2u) + 1u;
    char *destination = (char *) calloc(required, sizeof(char));
    if(destination == NULL) return 1;

    const int result = base64
        ? finish_hash_truncated64(TRUNCATION, HASH_SIGNATURE)(hash, destination, 0)
        : finish_hash_truncated(TRUNCATION, HASH_SIGNATURE)(hash, destination, 0);
    const int invalid = result != 0 || strlen(destination) != required - 1;
    free(destination);
    return invalid;
}
#endif

static int check_cipher_api(void) {
    static const char key[] = "c-api-key";
    static const char salt[BLOCK_SIZE] = {0};
    static const char input[BLOCK_SIZE] = "c-api";
    uint8_t encrypted[BLOCK_SIZE];
    uint8_t decrypted[BLOCK_SIZE];
    uint8_t derived[16];

    const size_t digest_size = get_hmac_size(BLOCK_SIZE, HASH_SIGNATURE)();
    uint8_t *digest = (uint8_t *) malloc(digest_size);
    if(get_default_shuffle_iterations(HASH_SIGNATURE)() == 0 || !digest ||
       hmac(BLOCK_SIZE, HASH_SIGNATURE)(sizeof(key) - 1, key, sizeof(input), input,
                                        digest, digest_size) != 0 ||
       pbkdf2(BLOCK_SIZE, HASH_SIGNATURE)(sizeof(key) - 1, key, sizeof(salt), salt,
                                          1, derived, sizeof(derived)) != 0 ||
       shuffle_encrypt(BLOCK_SIZE, HASH_SIGNATURE)(sizeof(key) - 1, key, sizeof(salt), salt,
                                                   sizeof(input), input, 1,
                                                   encrypted, sizeof(encrypted)) != 0 ||
       shuffle_decrypt(BLOCK_SIZE, HASH_SIGNATURE)(sizeof(key) - 1, key, sizeof(salt), salt,
                                                   sizeof(encrypted), (const char *) encrypted, 1,
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

int main(void) {
    if(check_full_digest(0) || check_full_digest(1) || check_cipher_api()) return 1;
#ifdef TRUNCATION
    if(check_truncated_digest(0) || check_truncated_digest(1)) return 1;
#endif
    return 0;
}

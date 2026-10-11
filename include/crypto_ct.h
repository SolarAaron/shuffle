// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef C_GUARD_SLR_CRYPTO_CT
#define C_GUARD_SLR_CRYPTO_CT

#include "crypto_c.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLR_CRYPTO_DETAIL_TRUNCATION_APPEND(prefix, truncation, variant) \
    prefix##T##truncation##_##variant
#define SLR_CRYPTO_DETAIL_TRUNCATION_API_APPEND_INNER(prefix, truncation, block_size, variant) \
    prefix##T##truncation##_##block_size##_##variant
#define SLR_CRYPTO_DETAIL_TRUNCATION_API_APPEND(prefix, truncation, block_size, variant) \
    SLR_CRYPTO_DETAIL_TRUNCATION_API_APPEND_INNER(prefix, truncation, block_size, variant)

#define finish_hash_truncated(truncation, variant) \
    SLR_CRYPTO_DETAIL_TRUNCATION_APPEND(finish_hash_, truncation, variant)
#define finish_hash_truncated64(truncation, variant) \
    SLR_CRYPTO_DETAIL_TRUNCATION_APPEND(finish_hash64_, truncation, variant)
#define get_hmac_size_truncated(truncation, block_size, variant) \
    SLR_CRYPTO_DETAIL_TRUNCATION_API_APPEND(get_hmac_size_, truncation, block_size, variant)
#define hmac_truncated(truncation, block_size, variant) \
    SLR_CRYPTO_DETAIL_TRUNCATION_API_APPEND(hmac_, truncation, block_size, variant)
#define pbkdf2_truncated(truncation, block_size, variant) \
    SLR_CRYPTO_DETAIL_TRUNCATION_API_APPEND(pbkdf2_, truncation, block_size, variant)
#define shuffle_encrypt_truncated(truncation, block_size, variant) \
    SLR_CRYPTO_DETAIL_TRUNCATION_API_APPEND(shuffle_, truncation, block_size, variant)
#define shuffle_decrypt_truncated(truncation, block_size, variant) \
    SLR_CRYPTO_DETAIL_TRUNCATION_API_APPEND(deshuffle_, truncation, block_size, variant)

#ifdef HASH_SIGNATURE
#ifdef TRUNCATION

int
finish_hash_truncated(TRUNCATION, HASH_SIGNATURE)(struct poker_hash_sum const *const hash, char *destination, size_t offset);

int
finish_hash_truncated64(TRUNCATION, HASH_SIGNATURE)(struct poker_hash_sum const *const hash, char *destination, size_t offset);

#ifdef BLOCK_SIZE
size_t
get_hmac_size_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)(void);

int
hmac_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)(size_t key_length, char const *key,
                                                       size_t message_length, char const *message,
                                                       uint8_t *destination, size_t destination_length);

int
pbkdf2_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)(size_t password_length, char const *password,
                                                         size_t salt_length, char const *salt,
                                                         int32_t iterations, uint8_t *destination,
                                                         size_t destination_length);

int
shuffle_encrypt_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)(
    size_t password_length, char const *password, size_t salt_length, char const *salt,
    size_t input_length, char const *input, size_t iterations,
    uint8_t *destination, size_t destination_length);

int
shuffle_decrypt_truncated(TRUNCATION, BLOCK_SIZE, HASH_SIGNATURE)(
    size_t password_length, char const *password, size_t salt_length, char const *salt,
    size_t input_length, char const *input, size_t iterations,
    uint8_t *destination, size_t destination_length);
#endif /* BLOCK_SIZE */

#endif /*TRUNCATION*/
#endif /*HASH_SIGNATURE*/

#ifdef __cplusplus
}
#endif

#endif //C_GUARD_SLR_CRYPTO_CT

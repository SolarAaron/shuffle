// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef C_GUARD_SLR_CRYPTO
#define C_GUARD_SLR_CRYPTO

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
struct poker_hash_sum {
    virtual ~poker_hash_sum();
};

#include <slr.crypto.hpp>

template<size_t... X>
struct poker_hash_impl : poker_hash_sum {
    std::bitset<slr::crypto::SC<X...>::value8>* hash{};
    size_t size = (slr::crypto::SC<X...>::value * 2) + 1;
    size_t size64 = (slr::crypto::SC<X...>::value8 + 5) / 6 + 1;

    ~poker_hash_impl() override {
        delete hash;
    }
};

extern "C" {
#else
struct poker_hash_sum;
#endif

#define SLR_CRYPTO_DETAIL_VARIANT_APPEND_INNER(prefix, variant) prefix##variant
#define SLR_CRYPTO_DETAIL_VARIANT_APPEND(prefix, variant) \
    SLR_CRYPTO_DETAIL_VARIANT_APPEND_INNER(prefix, variant)
#define SLR_CRYPTO_DETAIL_API_APPEND_INNER(prefix, block_size, variant) \
    prefix##block_size##_##variant
#define SLR_CRYPTO_DETAIL_API_APPEND(prefix, block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND_INNER(prefix, block_size, variant)

#define init_poker_hash(variant) \
    SLR_CRYPTO_DETAIL_VARIANT_APPEND(init_poker_hash_, variant)
#define hash_block(variant) \
    SLR_CRYPTO_DETAIL_VARIANT_APPEND(hash_block_, variant)
#define get_hash_size(variant) \
    SLR_CRYPTO_DETAIL_VARIANT_APPEND(get_hash_size_, variant)
#define finish_hash(variant) \
    SLR_CRYPTO_DETAIL_VARIANT_APPEND(finish_hash_, variant)
#define get_hash64_size(variant) \
    SLR_CRYPTO_DETAIL_VARIANT_APPEND(get_hash64_size_, variant)
#define finish_hash64(variant) \
    SLR_CRYPTO_DETAIL_VARIANT_APPEND(finish_hash64_, variant)
#define get_default_shuffle_iterations(variant) \
    SLR_CRYPTO_DETAIL_VARIANT_APPEND(get_default_shuffle_iterations_, variant)
#define get_hmac_size(block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND(get_hmac_size_, block_size, variant)
#define hmac(block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND(hmac_, block_size, variant)
#define pbkdf2(block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND(pbkdf2_, block_size, variant)
#define shuffle_encrypt(block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND(shuffle_, block_size, variant)
#define shuffle_decrypt(block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND(deshuffle_, block_size, variant)

#ifdef HASH_SIGNATURE

struct poker_hash_sum const *
init_poker_hash(HASH_SIGNATURE)(void);

int
hash_block(HASH_SIGNATURE)(struct poker_hash_sum const *const current,
                           char const *buffer, size_t length, size_t offset);

size_t
get_hash_size(HASH_SIGNATURE)(struct poker_hash_sum const *const hash);

size_t
get_hash64_size(HASH_SIGNATURE)(struct poker_hash_sum const *const hash);

int
finish_hash(HASH_SIGNATURE)(struct poker_hash_sum const *const hash,
                            char *destination, size_t offset);

int
finish_hash64(HASH_SIGNATURE)(struct poker_hash_sum const *const hash,
                              char *destination, size_t offset);

size_t
get_default_shuffle_iterations(HASH_SIGNATURE)(void);

#ifdef BLOCK_SIZE
size_t
get_hmac_size(BLOCK_SIZE, HASH_SIGNATURE)(void);

int
hmac(BLOCK_SIZE, HASH_SIGNATURE)(size_t key_length, char const *key,
                                 size_t message_length, char const *message,
                                 uint8_t *destination, size_t destination_length);

int
pbkdf2(BLOCK_SIZE, HASH_SIGNATURE)(size_t password_length, char const *password,
                                   size_t salt_length, char const *salt,
                                   int32_t iterations, uint8_t *destination,
                                   size_t destination_length);

int
shuffle_encrypt(BLOCK_SIZE, HASH_SIGNATURE)(size_t password_length, char const *password,
                                            size_t salt_length, char const *salt,
                                            size_t input_length, char const *input,
                                            size_t iterations, uint8_t *destination,
                                            size_t destination_length);

int
shuffle_decrypt(BLOCK_SIZE, HASH_SIGNATURE)(size_t password_length, char const *password,
                                            size_t salt_length, char const *salt,
                                            size_t input_length, char const *input,
                                            size_t iterations, uint8_t *destination,
                                            size_t destination_length);
#endif /* BLOCK_SIZE */

#endif /* HASH_SIGNATURE */

#ifdef __cplusplus
}
#endif

#endif /* C_GUARD_SLR_CRYPTO */

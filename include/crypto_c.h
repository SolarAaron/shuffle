// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef C_GUARD_SLR_CRYPTO
#define C_GUARD_SLR_CRYPTO

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
/** Opaque, variant-specific incremental Poker hash state. */
struct poker_hash_sum {
    virtual ~poker_hash_sum();
};
}
#include <slr.crypto.hpp>

/** C++ implementation detail backing the opaque C hash handle. */
template<size_t... Factors>
struct PokerHashImpl final : poker_hash_sum {
    /** Owned C++ hash state. */
    std::bitset<slr::crypto::VariantSize<Factors...>::bitCount>* hashState{};
    /** Required hexadecimal destination size, including terminator space. */
    size_t hexDestinationSize =
        (slr::crypto::VariantSize<Factors...>::byteCount * 2) + 1;
    /** Required Base64 destination size, including terminator space. */
    size_t base64DestinationSize =
        ((slr::crypto::VariantSize<Factors...>::bitCount + 5) / 6) + 1;

    ~PokerHashImpl() override {
        delete hashState;
    }
};

/** Compatibility alias for the former C++ implementation type name. */
template<size_t... Factors>
using poker_hash_impl = PokerHashImpl<Factors...>;

extern "C" {
#else
/** Opaque, variant-specific incremental Poker hash state. */
struct poker_hash_sum;
#endif

/* Internal token-pasting helpers use a project prefix to avoid collisions. */
#define SLR_CRYPTO_DETAIL_VARIANT_APPEND(a, b) a##b
#define SLR_CRYPTO_DETAIL_API_APPEND_INNER(prefix, block_size, variant) \
    prefix##block_size##_##variant
#define SLR_CRYPTO_DETAIL_API_APPEND(prefix, block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND_INNER(prefix, block_size, variant)

/** Maps a configured variant number to its exported incremental-hash symbol. */
#define init_poker_hash(variant) SLR_CRYPTO_DETAIL_VARIANT_APPEND(init_poker_hash_, variant)
#define hash_block(variant) SLR_CRYPTO_DETAIL_VARIANT_APPEND(hash_block_, variant)
#define get_hash_size(variant) SLR_CRYPTO_DETAIL_VARIANT_APPEND(get_hash_size_, variant)
#define finish_hash(variant) SLR_CRYPTO_DETAIL_VARIANT_APPEND(finish_hash_, variant)
#define get_hash64_size(variant) SLR_CRYPTO_DETAIL_VARIANT_APPEND(get_hash64_size_, variant)
#define finish_hash64(variant) SLR_CRYPTO_DETAIL_VARIANT_APPEND(finish_hash64_, variant)
#define get_default_shuffle_iterations(variant) \
    SLR_CRYPTO_DETAIL_VARIANT_APPEND(get_default_shuffle_iterations_, variant)
#define get_hmac_size(block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND(get_hmac_size_, block_size, variant)
#define hmac(block_size, variant) SLR_CRYPTO_DETAIL_API_APPEND(hmac_, block_size, variant)
#define pbkdf2(block_size, variant) SLR_CRYPTO_DETAIL_API_APPEND(pbkdf2_, block_size, variant)
#define shuffle_encrypt(block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND(shuffle_, block_size, variant)
#define shuffle_decrypt(block_size, variant) \
    SLR_CRYPTO_DETAIL_API_APPEND(deshuffle_, block_size, variant)

#ifdef HASH_SIGNATURE

/** Allocates an empty incremental hash. Pass the result to the same variant's functions. */
struct poker_hash_sum const *
init_poker_hash(HASH_SIGNATURE)(void);

/** Absorbs `length` bytes starting at `buffer + offset`; returns zero on success. */
int
hash_block(HASH_SIGNATURE)(struct poker_hash_sum const *const current, char const *buffer, size_t length, size_t offset);

/** Returns the required hexadecimal destination size, including one byte for a terminator. */
size_t
get_hash_size(HASH_SIGNATURE)(struct poker_hash_sum const *const hash);

/** Returns the required Base64 destination size, including one byte for a terminator. */
size_t
get_hash64_size(HASH_SIGNATURE)(struct poker_hash_sum const *const hash);

/**
 * Writes the hexadecimal digest at `destination + offset` and consumes `hash`.
 * Exactly `get_hash_size(hash) - 1` bytes are written; no terminator is written.
 * Returns zero on success and -1 if the handle has the wrong variant.
 */
int
finish_hash(HASH_SIGNATURE)(struct poker_hash_sum const *const hash, char *destination, size_t offset);

/**
 * Writes the unpadded Base64 digest at `destination + offset` and consumes `hash`.
 * Exactly `get_hash64_size(hash) - 1` bytes are written; no terminator is written.
 * Returns zero on success and -1 if the handle has the wrong variant.
 */
int
finish_hash64(HASH_SIGNATURE)(struct poker_hash_sum const *const hash, char *destination, size_t offset);

/** Returns the default PBKDF iteration count for this hash variant. */
size_t
get_default_shuffle_iterations(HASH_SIGNATURE)(void);

#ifdef BLOCK_SIZE
/*
 * The following operations return zero on success and -1 for invalid buffers,
 * insufficient destination space, invalid iteration counts, or other failures.
 * A null input pointer is accepted only when its corresponding byte length is zero.
 * The caller owns every destination buffer.
 */
/** Returns the HMAC digest size in bytes. */
size_t
get_hmac_size(BLOCK_SIZE, HASH_SIGNATURE)(void);

/** Writes one HMAC digest; `destination_length` must be at least `get_hmac_size()`. */
int
hmac(BLOCK_SIZE, HASH_SIGNATURE)(size_t key_length, char const *key,
                                 size_t message_length, char const *message,
                                 uint8_t *destination, size_t destination_length);

/** Derives exactly `destination_length` bytes; `iterations` must be positive. */
int
pbkdf2(BLOCK_SIZE, HASH_SIGNATURE)(size_t password_length, char const *password,
                                   size_t salt_length, char const *salt,
                                   int32_t iterations, uint8_t *destination,
                                   size_t destination_length);

/** Encrypts one `BLOCK_SIZE`-byte block, zero-padding a shorter input. */
int
shuffle_encrypt(BLOCK_SIZE, HASH_SIGNATURE)(size_t password_length, char const *password,
                                            size_t salt_length, char const *salt,
                                            size_t input_length, char const *input,
                                            size_t iterations, uint8_t *destination,
                                            size_t destination_length);

/** Decrypts one `BLOCK_SIZE`-byte block using matching encryption parameters. */
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

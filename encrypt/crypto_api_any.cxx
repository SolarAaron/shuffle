// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "crypto_ct.h"
#include "slr.crypto.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {
    constexpr char emptyBuffer = 0;

    const char* readable(const char* buffer, size_t length) {
        return buffer ? buffer : (length == 0 ? &emptyBuffer : nullptr);
    }

    template<size_t BlockSize, size_t HashBits, size_t... X>
    int apiHmac(size_t keyLength, const char* key, size_t messageLength, const char* message,
                uint8_t* destination, size_t destinationLength) {
        key = readable(key, keyLength);
        message = readable(message, messageLength);
        constexpr size_t digestBytes = (HashBits + 7) / 8;
        if(!key || !message || !destination || destinationLength < digestBytes) return -1;
        try {
            std::vector<uint8_t> innerKey, outerKey;
            slr::crypto::prepareHmacPadsTruncated<BlockSize, HashBits, X...>(
                keyLength, key, innerKey, outerKey);
            const auto result = slr::crypto::hmacWithPadsTruncated<HashBits, X...>(
                innerKey, outerKey, messageLength, message);
            std::copy(result.begin(), result.end(), destination);
            return 0;
        } catch(...) {
            return -1;
        }
    }

    template<size_t BlockSize, size_t HashBits, size_t... X>
    int apiPbkdf2(size_t passwordLength, const char* password, size_t saltLength, const char* salt,
                  int32_t iterations, uint8_t* destination, size_t destinationLength) {
        password = readable(password, passwordLength);
        salt = readable(salt, saltLength);
        if(!password || !salt || (!destination && destinationLength != 0)) return -1;
        try {
            const auto result = slr::crypto::pbkdf2Truncated<BlockSize, HashBits, X...>(
                passwordLength, password, saltLength, salt, iterations, destinationLength);
            std::copy(result.begin(), result.end(), destination);
            return 0;
        } catch(...) {
            return -1;
        }
    }

    template<bool Encrypt, size_t BlockSize, size_t HashBits, size_t... X>
    int apiShuffle(size_t passwordLength, const char* password, size_t saltLength, const char* salt,
                   size_t inputLength, const char* input, size_t iterations,
                   uint8_t* destination, size_t destinationLength) {
        password = readable(password, passwordLength);
        salt = readable(salt, saltLength);
        input = readable(input, inputLength);
        if(!password || !salt || !input || !destination || destinationLength < BlockSize) return -1;
        try {
            const auto result = [&] {
                if constexpr(Encrypt) {
                    return slr::crypto::shuffleEncryptTruncated<BlockSize, HashBits, X...>(
                        passwordLength, password, saltLength, salt, inputLength, input, iterations);
                } else {
                    return slr::crypto::shuffleDecryptTruncated<BlockSize, HashBits, X...>(
                        passwordLength, password, saltLength, salt, inputLength, input, iterations);
                }
            }();
            std::copy(result.begin(), result.end(), destination);
            return 0;
        } catch(...) {
            return -1;
        }
    }
}

#ifdef TRUNCATION
#define API_HASH_BITS TRUNCATION
#define API_HMAC_SIZE(block_size) get_hmac_size_truncated(TRUNCATION, block_size, HASH_SIGNATURE)
#define API_HMAC(block_size) hmac_truncated(TRUNCATION, block_size, HASH_SIGNATURE)
#define API_PBKDF2(block_size) pbkdf2_truncated(TRUNCATION, block_size, HASH_SIGNATURE)
#define API_SHUFFLE(block_size) shuffle_encrypt_truncated(TRUNCATION, block_size, HASH_SIGNATURE)
#define API_DESHUFFLE(block_size) shuffle_decrypt_truncated(TRUNCATION, block_size, HASH_SIGNATURE)
#else
#define API_HASH_BITS slr::crypto::VariantSize<HASH_DEFINITION>::bitCount
#define API_HMAC_SIZE(block_size) get_hmac_size(block_size, HASH_SIGNATURE)
#define API_HMAC(block_size) hmac(block_size, HASH_SIGNATURE)
#define API_PBKDF2(block_size) pbkdf2(block_size, HASH_SIGNATURE)
#define API_SHUFFLE(block_size) shuffle_encrypt(block_size, HASH_SIGNATURE)
#define API_DESHUFFLE(block_size) shuffle_decrypt(block_size, HASH_SIGNATURE)
#endif

#define DEFINE_CRYPTO_API(block_size) \
extern "C" size_t API_HMAC_SIZE(block_size)(void) { \
    return (API_HASH_BITS + 7) / 8; \
} \
extern "C" int API_HMAC(block_size)(size_t keyLength, const char* key, \
                                     size_t messageLength, const char* message, \
                                     uint8_t* destination, size_t destinationLength) { \
    return apiHmac<block_size, API_HASH_BITS, HASH_DEFINITION>( \
        keyLength, key, messageLength, message, destination, destinationLength); \
} \
extern "C" int API_PBKDF2(block_size)(size_t passwordLength, const char* password, \
                                       size_t saltLength, const char* salt, int32_t iterations, \
                                       uint8_t* destination, size_t destinationLength) { \
    return apiPbkdf2<block_size, API_HASH_BITS, HASH_DEFINITION>( \
        passwordLength, password, saltLength, salt, iterations, destination, destinationLength); \
} \
extern "C" int API_SHUFFLE(block_size)(size_t passwordLength, const char* password, \
                                        size_t saltLength, const char* salt, size_t inputLength, \
                                        const char* input, size_t iterations, uint8_t* destination, \
                                        size_t destinationLength) { \
    return apiShuffle<true, block_size, API_HASH_BITS, HASH_DEFINITION>( \
        passwordLength, password, saltLength, salt, inputLength, input, iterations, \
        destination, destinationLength); \
} \
extern "C" int API_DESHUFFLE(block_size)(size_t passwordLength, const char* password, \
                                          size_t saltLength, const char* salt, size_t inputLength, \
                                          const char* input, size_t iterations, uint8_t* destination, \
                                          size_t destinationLength) { \
    return apiShuffle<false, block_size, API_HASH_BITS, HASH_DEFINITION>( \
        passwordLength, password, saltLength, salt, inputLength, input, iterations, \
        destination, destinationLength); \
}

DEFINE_CRYPTO_API(BLOCK_SIZE)

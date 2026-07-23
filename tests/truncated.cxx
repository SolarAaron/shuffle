// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "crypto_ct.h"

#include <cstddef>
#include <iostream>
#include <string>
#include <vector>

namespace {
    constexpr char message[] = "configured truncated regression";
    constexpr std::size_t messageSize = sizeof(message) - 1;
    constexpr std::size_t bitCount = slr::crypto::VariantSize<HASH_DEFINITION>::bitCount;

    int fail(const char* messageText) {
        std::cerr << "variant " << VARIANT_NAME << ", truncation " << TRUNCATION
                  << ": " << messageText << '\n';
        return 1;
    }

    const poker_hash_sum* makeCHash() {
        const poker_hash_sum* hash = init_poker_hash(HASH_SIGNATURE)();
        if(hash && (hash_block(HASH_SIGNATURE)(hash, message, 9, 0) != 0 ||
                    hash_block(HASH_SIGNATURE)(hash, message, messageSize - 9, 9) != 0)) {
            return nullptr;
        }
        return hash;
    }
}

int main() {
    static_assert(TRUNCATION > 0);

    auto oneShot = slr::crypto::hashBlock<HASH_DEFINITION>(messageSize, message);
    auto oneShotTruncated = slr::crypto::truncate<bitCount, TRUNCATION>(oneShot);
    const std::string expectedHex = slr::crypto::finishHash(oneShotTruncated);
    const std::string expected64 = slr::crypto::finishHash64(oneShotTruncated);
    delete oneShotTruncated;
    delete oneShot;

    auto chunked = slr::crypto::hashBlock<HASH_DEFINITION>(0, nullptr);
    slr::crypto::hashBlock<HASH_DEFINITION>(9, message, chunked);
    slr::crypto::hashBlock<HASH_DEFINITION>(messageSize - 9, message + 9, chunked);
    auto chunkedTruncated = slr::crypto::truncate<bitCount, TRUNCATION>(chunked);
    const std::string chunkedHex = slr::crypto::finishHash(chunkedTruncated);
    const std::string chunked64 = slr::crypto::finishHash64(chunkedTruncated);
    delete chunkedTruncated;
    delete chunked;

    if(chunkedHex != expectedHex || chunked64 != expected64) {
        return fail("one-shot and chunked truncated hashes differ");
    }

    const poker_hash_sum* cHexHash = makeCHash();
    if(!cHexHash) return fail("C interface failed to create the hexadecimal hash state");
    std::vector<char> hexDestination(expectedHex.size() + 1, '\0');
    if(finish_hash_truncated(TRUNCATION, HASH_SIGNATURE)(cHexHash, hexDestination.data(), 0) != 0 ||
       std::string(hexDestination.data()) != expectedHex) {
        return fail("C and C++ hexadecimal truncation differ");
    }

    const poker_hash_sum* c64Hash = makeCHash();
    if(!c64Hash) return fail("C interface failed to create the Base64 hash state");
    std::vector<char> base64Destination(expected64.size() + 1, '\0');
    if(finish_hash_truncated64(TRUNCATION, HASH_SIGNATURE)(c64Hash, base64Destination.data(), 0) != 0 ||
       std::string(base64Destination.data()) != expected64) {
        return fail("C and C++ Base64 truncation differ");
    }

    return 0;
}

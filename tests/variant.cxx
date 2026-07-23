// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "crypto_c.h"

#include <algorithm>
#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace {
    constexpr std::size_t bitCount = slr::crypto::VariantSize<HASH_DEFINITION>::bitCount;
    using Bits = std::bitset<bitCount>;

    bool verifyPermutation(const Bits& source) {
        std::array<Bits, 1> input{source};
        Bits recursive;
        slr::crypto::BitFiddler<slr::crypto::VariantSize<HASH_DEFINITION>::byteCount,
                                bitCount, 1, HASH_DEFINITION>::bitwisePass(&recursive, &input);
        return recursive == slr::crypto::permuteBits<HASH_DEFINITION>(source);
    }

    bool verifyByteAbsorption(std::uint8_t byte) {
        auto composed = slr::crypto::initialPackedHashState<HASH_DEFINITION>();
        const char input = static_cast<char>(byte);
        slr::crypto::absorbPackedHash<HASH_DEFINITION>(1, &input, composed);

        auto sequential = slr::crypto::initialPackedHashState<HASH_DEFINITION>();
        decltype(sequential) scratch{};
        const auto& transitions = slr::crypto::hashTransitions<HASH_DEFINITION>();
        auto* current = &sequential;
        auto* next = &scratch;
        for(std::size_t round = 0; round < 8; ++round) {
            const std::uint8_t injection = static_cast<std::uint8_t>(
                ((byte >> round) & 1U) | (((byte >> (7 - round)) & 1U) << 1));
            slr::crypto::packedHashRound<HASH_DEFINITION>(*current, *next, transitions, injection);
            std::swap(current, next);
        }
        return composed == *current;
    }

    int fail(const char* message) {
        std::cerr << "variant " << VARIANT_NAME << ": " << message << '\n';
        return 1;
    }
}

int main() {
    static_assert(bitCount == EXPECTED_BITS,
                  "variant width must equal eight times the square of its multiplicative value");

    Bits alternating;
    Bits pseudoRandom;
    for(std::size_t bit = 0; bit < bitCount; ++bit) {
        alternating[bit] = bit % 2;
        pseudoRandom[bit] = ((bit * 17 + bit / 3 + 5) % 11) < 5;
    }
    if(!verifyPermutation(Bits{}) || !verifyPermutation(~Bits{}) ||
       !verifyPermutation(alternating) || !verifyPermutation(pseudoRandom)) {
        return fail("cached permutation differs from recursive BitFiddler output");
    }
    if(!verifyByteAbsorption(0x00) || !verifyByteAbsorption(0x01) ||
       !verifyByteAbsorption(0x80) || !verifyByteAbsorption(0xa5) ||
       !verifyByteAbsorption(0xff)) {
        return fail("byte absorption differs from eight sequential bit rounds");
    }

    const char avalancheBaseInput = 0;
    auto avalancheBase = slr::crypto::hashBlock<HASH_DEFINITION>(1, &avalancheBaseInput);
    for(std::size_t bit = 0; bit < 8; ++bit) {
        const char changedInput = static_cast<char>(1U << bit);
        auto changed = slr::crypto::hashBlock<HASH_DEFINITION>(1, &changedInput);
        const bool unchanged = *changed == *avalancheBase;
        delete changed;
        if(unchanged) {
            delete avalancheBase;
            return fail("a single input-bit change did not affect the digest");
        }
    }
    delete avalancheBase;

    constexpr char message[] = "configured variant regression";
    constexpr std::size_t messageSize = sizeof(message) - 1;
    auto oneShot = slr::crypto::hashBlock<HASH_DEFINITION>(messageSize, message);
    const std::string expected = slr::crypto::finishHash(oneShot);

    auto packed = slr::crypto::initialPackedHashState<HASH_DEFINITION>();
    slr::crypto::absorbPackedHash<HASH_DEFINITION>(messageSize, message, packed);
    const auto packedBytes = slr::crypto::packTruncatedHash<bitCount, HASH_DEFINITION>(packed);
    const auto bitsetBytes = slr::crypto::packBitsToBytes(oneShot);
    if(packedBytes != bitsetBytes) {
        delete oneShot;
        return fail("packed and bitset hash states differ");
    }
    delete oneShot;

    std::array<std::uint8_t, 32> arrayInput{};
    std::vector<std::uint8_t> vectorInput(arrayInput.size());
    for(std::size_t index = 0; index < arrayInput.size(); ++index) {
        arrayInput[index] = vectorInput[index] = static_cast<std::uint8_t>(index);
    }
    for(std::size_t splits = 1; splits <= 17; ++splits) {
        const auto shuffledArray = slr::crypto::shuffleArray(arrayInput, splits);
        const auto shuffledVector = slr::crypto::shuffleBlock(vectorInput, splits);
        if(!std::equal(shuffledArray.begin(), shuffledArray.end(), shuffledVector.begin()) ||
           slr::crypto::reverseShuffleArray(shuffledArray, splits) != arrayInput) {
            return fail("fixed and dynamic shuffle permutations differ");
        }
    }

    auto chunked = slr::crypto::hashBlock<HASH_DEFINITION>(0, nullptr);
    slr::crypto::hashBlock<HASH_DEFINITION>(7, message, chunked);
    slr::crypto::hashBlock<HASH_DEFINITION>(messageSize - 7, message + 7, chunked);
    const std::string chunkedResult = slr::crypto::finishHash(chunked);
    delete chunked;
    if(chunkedResult != expected) return fail("chunked and one-shot hashes differ");
    if(expected.size() != bitCount / 4) return fail("hex digest has an unexpected size");

    const poker_hash_sum* cHash = init_poker_hash(HASH_SIGNATURE)();
    if(!cHash) return fail("C interface failed to initialize a hash");
    if(get_hash_size(HASH_SIGNATURE)(cHash) != expected.size() + 1) {
        return fail("C interface reported an unexpected hash size");
    }
    if(hash_block(HASH_SIGNATURE)(cHash, message, 7, 0) != 0 ||
       hash_block(HASH_SIGNATURE)(cHash, message, messageSize - 7, 7) != 0) {
        return fail("C interface rejected an input block");
    }

    std::vector<char> destination(expected.size() + 1, '\0');
    if(finish_hash(HASH_SIGNATURE)(cHash, destination.data(), 0) != 0) {
        return fail("C interface failed to finish a hash");
    }
    if(std::string(destination.data()) != expected) {
        return fail("C and C++ interfaces produced different hashes");
    }

    return 0;
}

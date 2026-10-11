// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "slr.crypto.hpp"

#include <algorithm>
#include <bitset>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

template<size_t S>
std::vector<uint8_t> referencePackBitsToBytes(const std::bitset<S>& block) {
    std::vector<uint8_t> result;
    for(size_t pos = S; pos > 0; pos -= 8) {
        std::bitset<8> bits;
        for(size_t bit = 8; bit > 0; --bit) bits[8 - bit] = block[pos - bit];
        result.insert(result.begin(), static_cast<uint8_t>(bits.to_ulong()));
    }
    return result;
}

template<size_t T, size_t... X>
std::vector<uint8_t> referencePackTruncatedHash(std::bitset<slr::crypto::SC<X...>::value8>* block) {
    if constexpr(T == slr::crypto::SC<X...>::value8) {
        return referencePackBitsToBytes(*block);
    } else {
        auto truncated = slr::crypto::truncate<slr::crypto::SC<X...>::value8, T>(block);
        auto result = slr::crypto::packLowBitsToBytes(truncated);
        delete truncated;
        return result;
    }
}

template<typename T>
std::vector<T> referenceShuffle(const std::vector<T>& source, size_t splits) {
    std::vector<T> result(source.size());
    size_t resultIndex = 0;
    const size_t bucketCount = std::min(splits, source.size());
    for(size_t bucket = 0; bucket < bucketCount; ++bucket) {
        size_t index = bucket + ((source.size() - 1 - bucket) / splits) * splits;
        for(;;) {
            result[resultIndex++] = source[index];
            if(index < splits) break;
            index -= splits;
        }
    }
    return result;
}

template<typename T>
std::vector<T> referenceReverseShuffle(const std::vector<T>& source, size_t splits) {
    std::vector<T> result(source.size());
    size_t sourceIndex = 0;
    const size_t bucketCount = std::min(splits, source.size());
    for(size_t bucket = 0; bucket < bucketCount; ++bucket) {
        size_t index = bucket + ((source.size() - 1 - bucket) / splits) * splits;
        for(;;) {
            result[index] = source[sourceIndex++];
            if(index < splits) break;
            index -= splits;
        }
    }
    return result;
}

template<size_t Bs, size_t T, size_t... X>
std::vector<uint8_t> referenceHmacTruncated(size_t keyLength, const char* keyBuffer,
                                            size_t msgLength, const char* msgBuffer) {
    std::vector<uint8_t> keyBytes(Bs, 0);
    if(keyLength > Bs) {
        auto keyHash = slr::crypto::hashBlockTruncated<T, X...>(keyLength, keyBuffer);
        if constexpr(T == slr::crypto::SC<X...>::value8) {
            keyBytes = referencePackBitsToBytes(*keyHash);
            keyBytes.resize(Bs);
        } else {
            const auto packedKey = slr::crypto::packLowBitsToBytes(keyHash);
            std::copy_n(packedKey.begin(), std::min(Bs, packedKey.size()), keyBytes.begin());
        }
        delete keyHash;
    } else if(keyLength != 0) {
        std::copy_n(reinterpret_cast<const uint8_t*>(keyBuffer), keyLength, keyBytes.begin());
    }

    std::vector<uint8_t> innerInput(Bs + msgLength), outerInput(Bs);
    for(size_t byte = 0; byte < Bs; ++byte) {
        innerInput[byte] = keyBytes[byte] ^ 0x36;
        outerInput[byte] = keyBytes[byte] ^ 0x5c;
    }
    if(msgLength != 0) {
        std::copy_n(reinterpret_cast<const uint8_t*>(msgBuffer), msgLength, innerInput.begin() + Bs);
    }

    auto innerHash = slr::crypto::hashBlock<X...>(
        innerInput.size(), reinterpret_cast<const char*>(innerInput.data()));
    const auto innerDigest = referencePackTruncatedHash<T, X...>(innerHash);
    delete innerHash;

    outerInput.insert(outerInput.end(), innerDigest.begin(), innerDigest.end());
    auto outerHash = slr::crypto::hashBlock<X...>(
        outerInput.size(), reinterpret_cast<const char*>(outerInput.data()));
    auto result = referencePackTruncatedHash<T, X...>(outerHash);
    delete outerHash;
    return result;
}

template<size_t Bs, size_t T, size_t... X>
std::vector<uint8_t> referencePbkdf2Truncated(size_t passLength, const char* passBuffer,
                                              size_t saltLength, const char* saltBuffer,
                                              int32_t iterations, size_t length) {
    constexpr size_t hashBytes = (T + 7) / 8;
    std::vector<uint8_t> result;
    for(uint32_t blockIndex = 1; result.size() < length; ++blockIndex) {
        std::vector<uint8_t> salt(saltLength + 4);
        if(saltLength != 0) {
            std::copy_n(reinterpret_cast<const uint8_t*>(saltBuffer), saltLength, salt.begin());
        }
        salt[saltLength] = static_cast<uint8_t>(blockIndex >> 24);
        salt[saltLength + 1] = static_cast<uint8_t>(blockIndex >> 16);
        salt[saltLength + 2] = static_cast<uint8_t>(blockIndex >> 8);
        salt[saltLength + 3] = static_cast<uint8_t>(blockIndex);

        auto current = referenceHmacTruncated<Bs, T, X...>(
            passLength, passBuffer, salt.size(), reinterpret_cast<const char*>(salt.data()));
        auto block = current;
        for(int32_t iteration = 1; iteration < iterations; ++iteration) {
            current = referenceHmacTruncated<Bs, T, X...>(
                passLength, passBuffer, current.size(), reinterpret_cast<const char*>(current.data()));
            for(size_t byte = 0; byte < block.size(); ++byte) block[byte] ^= current[byte];
        }
        const size_t count = std::min(hashBytes, length - result.size());
        result.insert(result.end(), block.begin(), block.begin() + count);
    }
    return result;
}

template<size_t Bs, size_t... X>
std::vector<uint8_t> referencePbkdf2(size_t passLength, const char* passBuffer,
                                     size_t saltLength, const char* saltBuffer,
                                     int32_t iterations, size_t length) {
    std::vector<uint8_t> result;
    int blockIndex = 1;
    while(result.size() < length) {
        std::vector<std::vector<uint8_t>> hashIter;
        std::vector<uint8_t> salt(saltLength);
        std::vector<uint8_t> counterBytes;
        std::copy_n(reinterpret_cast<const uint8_t*>(saltBuffer), saltLength, salt.begin());
        counterBytes.insert(counterBytes.begin(), blockIndex & 0xff);
        counterBytes.insert(counterBytes.begin(), (blockIndex >> 8) & 0xff);
        counterBytes.insert(counterBytes.begin(), (blockIndex >> 16) & 0xff);
        counterBytes.insert(counterBytes.begin(), (blockIndex >> 24) & 0xff);
        salt.insert(salt.end(), counterBytes.begin(), counterBytes.end());

        hashIter.push_back(slr::crypto::hmac<Bs, X...>(
            passLength, passBuffer, salt.size(), reinterpret_cast<const char*>(salt.data())));
        while(hashIter.size() < static_cast<size_t>(std::max(iterations, 1))) {
            hashIter.push_back(slr::crypto::hmac<Bs, X...>(
                passLength, passBuffer, hashIter.back().size(),
                reinterpret_cast<const char*>(hashIter.back().data())));
        }

        std::vector<uint8_t> block;
        for(const auto& value : hashIter) {
            if(block.size() < value.size()) block.resize(value.size());
            for(size_t byte = 0; byte < block.size(); ++byte) block[byte] ^= value[byte];
        }
        for(const auto byte : block) {
            if(result.size() < length) result.push_back(byte);
        }
        ++blockIndex;
    }
    return result;
}

int main() {
    std::bitset<5> fiveBits;
    fiveBits[0] = true;
    fiveBits[4] = true;
    if(slr::crypto::finishHash64(&fiveBits) != "R") {
        std::cerr << "partial base64 group was not right-aligned\n";
        return 1;
    }

    std::bitset<7> sevenBits;
    sevenBits[0] = true;
    sevenBits[1] = true;
    sevenBits[6] = true;
    if(slr::crypto::finishHash64(&sevenBits) != "Bh") {
        std::cerr << "right-aligned base64 changed subsequent six-bit groups\n";
        return 1;
    }

    std::bitset<6> fullBase64Group;
    fullBase64Group.set();
    if(slr::crypto::finishHash64(&fullBase64Group) != "/") {
        std::cerr << "complete base64 group changed\n";
        return 1;
    }

    for(size_t value = 0; value < 256; ++value) {
        const auto& injections = slr::crypto::hashByteInjections(static_cast<uint8_t>(value));
        for(size_t round = 0; round < injections.size(); ++round) {
            const auto byte = static_cast<uint8_t>(value);
            const auto expected = static_cast<uint8_t>(
                ((byte >> round) & 1U) | (((byte >> (7 - round)) & 1U) << 1));
            if(injections[round] != expected) {
                std::cerr << "hash byte injection table mismatch\n";
                return 1;
            }
        }
    }

    for(size_t pattern = 0; pattern < 130; ++pattern) {
        std::bitset<128> bits;
        if(pattern < bits.size()) bits.set(pattern);
        else {
            for(size_t bit = 0; bit < bits.size(); ++bit) {
                bits[bit] = ((bit * 29 + pattern * 17) % 7) < 3;
            }
        }
        if(slr::crypto::packBitsToBytes(&bits) != referencePackBitsToBytes(bits)) {
            std::cerr << "packed bitset bytes changed\n";
            return 1;
        }
    }

    for(size_t length = 0; length <= 48; ++length) {
        std::vector<uint8_t> source(length);
        std::vector<bool> boolSource(length);
        for(size_t index = 0; index < length; ++index) {
            source[index] = static_cast<uint8_t>(index * 37 + length);
            boolSource[index] = ((index * 13 + length) % 5) < 2;
        }
        for(size_t splits = 1; splits <= 52; ++splits) {
            std::vector<uint8_t> shuffled, reversed;
            slr::crypto::shuffleBlockInto(source, shuffled, splits);
            slr::crypto::reverseShuffleBlockInto(shuffled, reversed, splits);
            if(shuffled != referenceShuffle(source, splits) ||
               reversed != referenceReverseShuffle(shuffled, splits) || reversed != source) {
                std::cerr << "reusable shuffle permutation changed\n";
                return 1;
            }
            auto aliased = source;
            slr::crypto::shuffleBlockInto(aliased, aliased, splits);
            if(aliased != shuffled) {
                std::cerr << "in-place shuffle helper changed its permutation\n";
                return 1;
            }

            std::vector<bool> boolShuffled, boolReversed;
            slr::crypto::shuffleBlockInto(boolSource, boolShuffled, splits);
            slr::crypto::reverseShuffleBlockInto(boolShuffled, boolReversed, splits);
            if(boolShuffled != referenceShuffle(boolSource, splits) || boolReversed != boolSource) {
                std::cerr << "reusable bit shuffle permutation changed\n";
                return 1;
            }
        }
    }

    const char longKey[] = "0123456789abcdef-key-material";
    const char message[] = "output-preserving hmac test message";
    const char salt[] = "salt-data";
    const char empty[] = "";
    for(const size_t keyLength : {size_t(0), size_t(3), size_t(8), sizeof(longKey) - 1}) {
        const char* key = keyLength == 0 ? empty : longKey;
        for(const size_t messageLength : {size_t(0), size_t(1), sizeof(message) - 1}) {
            const char* messageBuffer = messageLength == 0 ? empty : message;
            const auto expected = referenceHmacTruncated<8, 20, 2>(
                keyLength, key, messageLength, messageBuffer);
            const auto actual = slr::crypto::hmacTruncated<8, 20, 2>(
                keyLength, key, messageLength, messageBuffer);
            if(actual != expected) {
                std::cerr << "prepared truncated HMAC output changed\n";
                return 1;
            }
        }
    }

    for(const size_t keyLength : {size_t(0), size_t(8), sizeof(longKey) - 1}) {
        const char* key = keyLength == 0 ? empty : longKey;
        const auto expected = referenceHmacTruncated<8, 32, 2>(
            keyLength, key, sizeof(message) - 1, message);
        const auto actual = slr::crypto::hmacTruncated<8, 32, 2>(
            keyLength, key, sizeof(message) - 1, message);
        if(actual != expected) {
            std::cerr << "full-width prepared HMAC output changed\n";
            return 1;
        }
    }

    for(const int32_t iterations : {1, 4}) {
        const auto expected = referencePbkdf2Truncated<8, 20, 2>(
            sizeof(longKey) - 1, longKey, sizeof(salt) - 1, salt, iterations, 37);
        const auto actual = slr::crypto::pbkdf2Truncated<8, 20, 2>(
            sizeof(longKey) - 1, longKey, sizeof(salt) - 1, salt, iterations, 37);
        if(actual != expected) {
            std::cerr << "prepared truncated PBKDF2 output changed\n";
            return 1;
        }
    }

    const auto fullExpected = referencePbkdf2Truncated<8, 32, 2>(
        sizeof(longKey) - 1, longKey, sizeof(salt) - 1, salt, 3, 19);
    const auto fullActual = slr::crypto::pbkdf2Truncated<8, 32, 2>(
        sizeof(longKey) - 1, longKey, sizeof(salt) - 1, salt, 3, 19);
    if(fullActual != fullExpected) {
        std::cerr << "full-width prepared truncated PBKDF2 output changed\n";
        return 1;
    }

    for(const int32_t iterations : {0, 3}) {
        const auto expected = referencePbkdf2<8, 2>(
            sizeof(longKey) - 1, longKey, sizeof(salt) - 1, salt, iterations, 29);
        const auto actual = slr::crypto::pbkdf2<8, 2>(
            sizeof(longKey) - 1, longKey, sizeof(salt) - 1, salt, iterations, 29);
        if(actual != expected) {
            std::cerr << "rolling legacy PBKDF2 output changed\n";
            return 1;
        }
    }

    return 0;
}

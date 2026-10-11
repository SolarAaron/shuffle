// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "slr.crypto.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

#ifndef SLR_TEST_VARIANT
#define SLR_TEST_VARIANT 2
#endif

int main() {
    constexpr size_t blockSize = 8;
    const char password[] = "context-test-key";
    std::array<uint8_t, blockSize> fileSalt{};
    for(size_t i = 0; i < fileSalt.size(); ++i) {
        fileSalt[i] = static_cast<uint8_t>(0xA0U + i);
    }

    using Context = slr::crypto::ShuffleKdfContext<blockSize, SLR_TEST_VARIANT>;
    Context encryptor(sizeof(password) - 1, password, fileSalt.size(),
                      reinterpret_cast<const char*>(fileSalt.data()), 3);
    Context decryptor(sizeof(password) - 1, password, fileSalt.size(),
                      reinterpret_cast<const char*>(fileSalt.data()), 3);

    std::array<uint8_t, blockSize> previous = fileSalt;
    for(std::uint64_t blockIndex = 0; blockIndex < 2; ++blockIndex) {
        std::array<uint8_t, blockSize> plaintext{};
        for(size_t i = 0; i < plaintext.size(); ++i) {
            plaintext[i] = static_cast<uint8_t>(blockIndex * 31 + i * 13);
        }
        const auto ciphertext = encryptor.encryptBlock(
            previous.size(), reinterpret_cast<const char*>(previous.data()), plaintext.size(),
            reinterpret_cast<const char*>(plaintext.data()), blockIndex);
        const auto recovered = decryptor.decryptBlock(
            previous.size(), reinterpret_cast<const char*>(previous.data()), ciphertext.size(),
            reinterpret_cast<const char*>(ciphertext.data()), blockIndex);
        if(ciphertext.size() != blockSize || recovered.size() != blockSize ||
           !std::equal(recovered.begin(), recovered.end(), plaintext.begin())) {
            std::cerr << "block round-trip failed at index " << blockIndex << '\n';
            return 1;
        }
        if(blockIndex == 0) {
            encryptor.setFileContext(ciphertext.size(), reinterpret_cast<const char*>(ciphertext.data()));
            decryptor.setFileContext(ciphertext.size(), reinterpret_cast<const char*>(ciphertext.data()));
        }
        std::copy(ciphertext.begin(), ciphertext.end(), previous.begin());
    }

    const auto encryptMask = encryptor.paddingMask(
        previous.size(), reinterpret_cast<const char*>(previous.data()), 2);
    const auto decryptMask = decryptor.paddingMask(
        previous.size(), reinterpret_cast<const char*>(previous.data()), 2);
    if(encryptMask != decryptMask || encryptMask.size() != blockSize) {
        std::cerr << "padding mask did not reproduce\n";
        return 1;
    }

    std::array<uint8_t, blockSize> padded = {};
    std::copy(encryptMask.begin(), encryptMask.end(), padded.begin());
    padded[0] = 0x11;
    padded[1] = 0x22;
    padded[2] = 0x33;
    const auto ciphertext = encryptor.encryptBlock(
        previous.size(), reinterpret_cast<const char*>(previous.data()), padded.size(),
        reinterpret_cast<const char*>(padded.data()), 2);
    const auto recovered = decryptor.decryptBlock(
        previous.size(), reinterpret_cast<const char*>(previous.data()), ciphertext.size(),
        reinterpret_cast<const char*>(ciphertext.data()), 2);
    if(ciphertext.size() != blockSize || recovered != std::vector<uint8_t>(padded.begin(), padded.end())) {
        std::cerr << "padded block round-trip failed\n";
        return 1;
    }

    const auto otherContext = encryptor.encryptBlock(
        previous.size(), reinterpret_cast<const char*>(previous.data()), padded.size(),
        reinterpret_cast<const char*>(padded.data()), 3);
    if(otherContext == ciphertext) {
        std::cerr << "block index was not bound into the expander context\n";
        return 1;
    }

    const auto singleBlockCiphertext = slr::crypto::shuffleEncrypt<blockSize, SLR_TEST_VARIANT>(
        sizeof(password) - 1, password, fileSalt.size(), reinterpret_cast<const char*>(fileSalt.data()),
        padded.size(), reinterpret_cast<const char*>(padded.data()), 3);
    const auto singleBlockRecovered = slr::crypto::shuffleDecrypt<blockSize, SLR_TEST_VARIANT>(
        sizeof(password) - 1, password, fileSalt.size(), reinterpret_cast<const char*>(fileSalt.data()),
        singleBlockCiphertext.size(), reinterpret_cast<const char*>(singleBlockCiphertext.data()), 3);
    if(singleBlockCiphertext.size() != blockSize ||
       singleBlockRecovered != std::vector<uint8_t>(padded.begin(), padded.end())) {
        std::cerr << "single-block API round-trip failed\n";
        return 1;
    }

    using TruncatedContext = slr::crypto::TruncatedShuffleKdfContext<
        blockSize, 20, SLR_TEST_VARIANT>;
    TruncatedContext truncatedEncryptor(
        sizeof(password) - 1, password, fileSalt.size(), reinterpret_cast<const char*>(fileSalt.data()), 3);
    TruncatedContext truncatedDecryptor(
        sizeof(password) - 1, password, fileSalt.size(), reinterpret_cast<const char*>(fileSalt.data()), 3);
    const auto truncatedIvCiphertext = truncatedEncryptor.encryptBlock(
        fileSalt.size(), reinterpret_cast<const char*>(fileSalt.data()), padded.size(),
        reinterpret_cast<const char*>(padded.data()), 0);
    const auto truncatedIvRecovered = truncatedDecryptor.decryptBlock(
        fileSalt.size(), reinterpret_cast<const char*>(fileSalt.data()), truncatedIvCiphertext.size(),
        reinterpret_cast<const char*>(truncatedIvCiphertext.data()), 0);
    if(truncatedIvCiphertext.size() != blockSize ||
       truncatedIvRecovered != std::vector<uint8_t>(padded.begin(), padded.end())) {
        std::cerr << "non-byte-aligned truncated shuffle round-trip failed\n";
        return 1;
    }

    truncatedEncryptor.setFileContext(
        truncatedIvCiphertext.size(), reinterpret_cast<const char*>(truncatedIvCiphertext.data()));
    truncatedDecryptor.setFileContext(
        truncatedIvCiphertext.size(), reinterpret_cast<const char*>(truncatedIvCiphertext.data()));
    std::array<uint8_t, blockSize> nextPlaintext{};
    for(size_t i = 0; i < nextPlaintext.size(); ++i) {
        nextPlaintext[i] = static_cast<uint8_t>(0xF0U - i * 7U);
    }
    const auto truncatedNextCiphertext = truncatedEncryptor.encryptBlock(
        truncatedIvCiphertext.size(), reinterpret_cast<const char*>(truncatedIvCiphertext.data()),
        nextPlaintext.size(), reinterpret_cast<const char*>(nextPlaintext.data()), 1);
    const auto truncatedNextRecovered = truncatedDecryptor.decryptBlock(
        truncatedIvCiphertext.size(), reinterpret_cast<const char*>(truncatedIvCiphertext.data()),
        truncatedNextCiphertext.size(), reinterpret_cast<const char*>(truncatedNextCiphertext.data()), 1);
    if(truncatedNextRecovered != std::vector<uint8_t>(nextPlaintext.begin(), nextPlaintext.end())) {
        std::cerr << "context-bound truncated shuffle round-trip failed\n";
        return 1;
    }

    return 0;
}

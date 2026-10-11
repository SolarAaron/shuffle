// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "file_format.hpp"
#include "slr.crypto.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

int main() {
    constexpr size_t blockSize = 8;
    static const char password[] = "file-format-test";
    std::array<uint8_t, blockSize> salt{};
    for(size_t byte = 0; byte < salt.size(); ++byte) salt[byte] = static_cast<uint8_t>(byte * 11 + 3);

    const std::array<size_t, 3> candidateBlockSizes{{8, 16, 32}};
    for(const size_t candidateBlockSize : candidateBlockSizes) {
        const auto candidate = shuffle_file_format::encodeHeader(5, candidateBlockSize);
        std::uint64_t candidateLength = 0;
        if(candidate.size() != shuffle_file_format::encryptedHeaderSize(candidateBlockSize) ||
           !shuffle_file_format::decodeHeader(candidate.data(), candidate.size(),
                                              candidateBlockSize, candidateLength) ||
           candidateLength != 5) {
            std::cerr << "padded header failed for block size " << candidateBlockSize << '\n';
            return 1;
        }
        if(candidate.size() > shuffle_file_format::headerPlaintextSize) {
            auto nonzeroPadding = candidate;
            nonzeroPadding.back() = 1;
            if(shuffle_file_format::decodeHeader(nonzeroPadding.data(), nonzeroPadding.size(),
                                                 candidateBlockSize, candidateLength)) {
                std::cerr << "nonzero encrypted-header padding was accepted\n";
                return 1;
            }
        }
    }

    using Context = slr::crypto::TruncatedShuffleKdfContext<blockSize, 20, 2>;
    Context encryptor(sizeof(password) - 1, password, salt.size(),
                      reinterpret_cast<const char*>(salt.data()), 2);
    Context decryptor(sizeof(password) - 1, password, salt.size(),
                      reinterpret_cast<const char*>(salt.data()), 2);

    std::array<uint8_t, blockSize> previous{};
    constexpr std::uint64_t plaintextLength = 5;
    const auto encodedHeader = shuffle_file_format::encodeHeader(plaintextLength, blockSize);
    std::vector<uint8_t> encryptedHeader(encodedHeader.size());
    std::vector<uint8_t> recoveredHeader(encodedHeader.size());
    constexpr size_t headerBlockCount = shuffle_file_format::encryptedHeaderSize(blockSize) / blockSize;
    for(size_t headerBlock = 0; headerBlock < headerBlockCount; ++headerBlock) {
        std::array<uint8_t, blockSize> plaintextBlock{};
        std::copy_n(encodedHeader.begin() + headerBlock * blockSize, blockSize, plaintextBlock.begin());
        const auto encryptedBlock = encryptor.encryptBlock(
            previous.size(), reinterpret_cast<const char*>(previous.data()), plaintextBlock.size(),
            reinterpret_cast<const char*>(plaintextBlock.data()), headerBlock);
        const auto recoveredBlock = decryptor.decryptBlock(
            previous.size(), reinterpret_cast<const char*>(previous.data()), encryptedBlock.size(),
            reinterpret_cast<const char*>(encryptedBlock.data()), headerBlock);
        if(headerBlock == 0) {
            encryptor.setFileContext(encryptedBlock.size(), reinterpret_cast<const char*>(encryptedBlock.data()));
            decryptor.setFileContext(encryptedBlock.size(), reinterpret_cast<const char*>(encryptedBlock.data()));
        }
        std::copy(encryptedBlock.begin(), encryptedBlock.end(), encryptedHeader.begin() + headerBlock * blockSize);
        std::copy(recoveredBlock.begin(), recoveredBlock.end(), recoveredHeader.begin() + headerBlock * blockSize);
        std::copy(encryptedBlock.begin(), encryptedBlock.end(), previous.begin());
    }
    std::uint64_t recoveredLength = 0;
    if(!shuffle_file_format::decodeHeader(recoveredHeader.data(), recoveredHeader.size(),
                                          blockSize, recoveredLength) ||
       recoveredLength != plaintextLength ||
       encodedHeader.size() != shuffle_file_format::encryptedHeaderSize(blockSize)) {
        std::cerr << "encrypted padded header did not round-trip\n";
        return 1;
    }

    const auto mask = encryptor.paddingMask(
        previous.size(), reinterpret_cast<const char*>(previous.data()), headerBlockCount);
    std::array<uint8_t, blockSize> finalPlaintextBlock{};
    std::copy(mask.begin(), mask.end(), finalPlaintextBlock.begin());
    std::array<uint8_t, plaintextLength> plaintext{{0x11, 0x22, 0x33, 0x44, 0x00}};
    plaintext.back() = mask[plaintext.size() - 1];
    if(plaintext[plaintext.size() - 2] == mask[plaintext.size() - 2]) {
        plaintext[plaintext.size() - 2] ^= 1;
    }
    std::copy(plaintext.begin(), plaintext.end(), finalPlaintextBlock.begin());

    const auto encryptedPayload = encryptor.encryptBlock(
        previous.size(), reinterpret_cast<const char*>(previous.data()), finalPlaintextBlock.size(),
        reinterpret_cast<const char*>(finalPlaintextBlock.data()), headerBlockCount);
    const auto recoveredPayload = decryptor.decryptBlock(
        previous.size(), reinterpret_cast<const char*>(previous.data()), encryptedPayload.size(),
        reinterpret_cast<const char*>(encryptedPayload.data()), headerBlockCount);
    if(!std::equal(plaintext.begin(), plaintext.end(), recoveredPayload.begin())) {
        std::cerr << "partial payload bytes were not recovered from explicit length\n";
        return 1;
    }

    size_t legacyTrimmedLength = blockSize;
    while(legacyTrimmedLength > 0 &&
          mask[legacyTrimmedLength - 1] == recoveredPayload[legacyTrimmedLength - 1]) {
        --legacyTrimmedLength;
    }
    if(legacyTrimmedLength == plaintext.size()) {
        std::cerr << "test vector did not exercise suffix-ambiguity case\n";
        return 1;
    }
    return 0;
}

// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "slr.crypto.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

template<typename Context>
bool verifyVectors(const char* password, const std::array<uint8_t, 8>& salt,
                   const std::array<uint8_t, 8>& expectedFirst,
                   const std::array<uint8_t, 8>& expectedNext) {
    Context encryptor(8, password, salt.size(), reinterpret_cast<const char*>(salt.data()), 3);
    std::array<uint8_t, 8> previous{};
    std::array<uint8_t, 8> firstPlaintext{{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
    auto firstCiphertext = encryptor.encryptBlock(
        previous.size(), reinterpret_cast<const char*>(previous.data()), firstPlaintext.size(),
        reinterpret_cast<const char*>(firstPlaintext.data()), 0);
    if(!std::equal(firstCiphertext.begin(), firstCiphertext.end(), expectedFirst.begin())) return false;
    encryptor.setFileContext(firstCiphertext.size(), reinterpret_cast<const char*>(firstCiphertext.data()));
    std::copy(firstCiphertext.begin(), firstCiphertext.end(), previous.begin());

    std::array<uint8_t, 8> nextPlaintext{{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe}};
    const auto nextCiphertext = encryptor.encryptBlock(
        previous.size(), reinterpret_cast<const char*>(previous.data()), nextPlaintext.size(),
        reinterpret_cast<const char*>(nextPlaintext.data()), 1);
    return std::equal(nextCiphertext.begin(), nextCiphertext.end(), expectedNext.begin());
}

int main() {
    static const char password[] = "cipher-output-test";
    const std::array<uint8_t, 8> salt{{0, 1, 2, 3, 4, 5, 6, 7}};
    if(!verifyVectors<slr::crypto::ShuffleKdfContext<8, 2>>(
           password, salt, {{0x98, 0x07, 0x90, 0x40, 0x9c, 0x2a, 0x2d, 0xb5}},
           {{0x2d, 0xfd, 0x7c, 0xdc, 0xd9, 0x6f, 0x20, 0xef}}) ||
       !verifyVectors<slr::crypto::TruncatedShuffleKdfContext<8, 20, 2>>(
           password, salt, {{0xa9, 0xce, 0x95, 0x6e, 0x09, 0x64, 0xe0, 0x9f}},
           {{0xb0, 0xc2, 0x25, 0x1c, 0x67, 0x27, 0x0f, 0x5f}})) {
        std::cerr << "per-block cipher output changed\n";
        return 1;
    }
    return 0;
}

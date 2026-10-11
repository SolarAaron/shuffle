// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef SHUFFLE_FILE_FORMAT_HPP
#define SHUFFLE_FILE_FORMAT_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace shuffle_file_format {
    inline constexpr std::array<uint8_t, 8> encryptedMagic{{'S', 'L', 'R', 'S', 'H', 'F', 'L', '4'}};
    inline constexpr size_t lengthFieldSize = 8;
    inline constexpr size_t headerPlaintextSize = encryptedMagic.size() + lengthFieldSize;

    inline constexpr size_t encryptedHeaderSize(size_t blockSize) noexcept {
        if(blockSize == 0) return 0;
        return ((headerPlaintextSize + blockSize - 1) / blockSize) * blockSize;
    }

    inline std::array<uint8_t, lengthFieldSize> encodeLength(std::uint64_t length) noexcept {
        std::array<uint8_t, lengthFieldSize> result{};
        for(size_t byte = 0; byte < result.size(); ++byte) {
            result[byte] = static_cast<uint8_t>(length >> (56 - byte * 8));
        }
        return result;
    }

    inline std::uint64_t decodeLength(const uint8_t* bytes) noexcept {
        std::uint64_t result = 0;
        for(size_t byte = 0; byte < lengthFieldSize; ++byte) {
            result = (result << 8) | bytes[byte];
        }
        return result;
    }

    inline std::vector<uint8_t> encodeHeader(std::uint64_t length, size_t blockSize) {
        if(blockSize == 0) return {};
        const size_t paddedSize = encryptedHeaderSize(blockSize);
        std::vector<uint8_t> result(paddedSize, 0);
        std::copy(encryptedMagic.begin(), encryptedMagic.end(), result.begin());
        const auto encodedLength = encodeLength(length);
        std::copy(encodedLength.begin(), encodedLength.end(), result.begin() + encryptedMagic.size());
        return result;
    }

    inline bool decodeHeader(const uint8_t* bytes, size_t size, size_t blockSize,
                             std::uint64_t& length) noexcept {
        if(bytes == nullptr || size != encryptedHeaderSize(blockSize) ||
           size < headerPlaintextSize ||
           !std::equal(encryptedMagic.begin(), encryptedMagic.end(), bytes)) {
            return false;
        }
        if(!std::all_of(bytes + headerPlaintextSize, bytes + size,
                        [](uint8_t byte) { return byte == 0; })) {
            return false;
        }
        length = decodeLength(bytes + encryptedMagic.size());
        return true;
    }
}

#endif // SHUFFLE_FILE_FORMAT_HPP

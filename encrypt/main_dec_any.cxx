// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

#include "args.hpp"
#include "file_format.hpp"
#include "slr.crypto.hpp"
#include "terminal_password.hpp"

#ifdef TRUNCATION
using CipherSession = slr::crypto::TruncatedShuffleKdfContext<BLOCK_SIZE, TRUNCATION, HASH_DEFINITION>;
#else
using CipherSession = slr::crypto::ShuffleKdfContext<BLOCK_SIZE, HASH_DEFINITION>;
#endif

int main(int argc, char** argv) {
    static_assert(BLOCK_SIZE >= shuffle_file_format::lengthFieldSize,
                  "the file format requires an eight-byte minimum block size");
    constexpr size_t headerCiphertextSize = shuffle_file_format::encryptedHeaderSize(BLOCK_SIZE);
    constexpr size_t headerBlockCount = headerCiphertextSize / BLOCK_SIZE;

    std::string keybuf;
    auto args = Args().parse(argc, argv);
    if(args.file_names.empty()) {
        std::cerr << "Usage: " << argv[0] << " [-k keyfile] file(s)" << std::endl;
        return 0;
    }

    if(args.use_keyfile) {
        std::istreambuf_iterator<char> eos;
        for(const auto& keyfileName : args.keyfile_names) {
            std::fstream keyfile(keyfileName, std::fstream::in | std::fstream::binary);
            if(!keyfile.is_open()) {
                std::cerr << "Unable to open key file " << keyfileName << std::endl;
                return 1;
            }
            keybuf.append(std::istreambuf_iterator<char>(keyfile), eos);
        }
    }

    const size_t iterations = args.iterations == 0
        ? slr::crypto::defaultShuffleIterations<HASH_DEFINITION>()
        : args.iterations;

    for(const auto& fileName : args.file_names) {
        std::string password;
        std::fstream file(fileName, std::fstream::in | std::fstream::binary);
        if(!file.is_open()) {
            std::cerr << "Unable to open input for " << fileName << std::endl;
            return 1;
        }

        file.seekg(0, std::ios::end);
        const std::streampos endPosition = file.tellg();
        if(endPosition == std::streampos(-1)) {
            std::cerr << "Unable to determine ciphertext size for " << fileName << std::endl;
            return 1;
        }
        const std::streamoff fileLength = static_cast<std::streamoff>(endPosition);
        if(fileLength < 0) {
            std::cerr << "Invalid ciphertext size for " << fileName << std::endl;
            return 1;
        }
        const auto ciphertextLength = static_cast<std::uint64_t>(fileLength);
        constexpr std::uint64_t fixedHeaderLength = BLOCK_SIZE + headerCiphertextSize;
        if(ciphertextLength < fixedHeaderLength) {
            std::cerr << "Ciphertext is missing its salt or encrypted header in " << fileName << std::endl;
            return 1;
        }
        file.seekg(0, std::ios::beg);
        if(!file) {
            std::cerr << "Unable to rewind input " << fileName << std::endl;
            return 1;
        }

        std::array<uint8_t, BLOCK_SIZE> kdfSalt{};
        file.read(reinterpret_cast<char*>(kdfSalt.data()), static_cast<std::streamsize>(kdfSalt.size()));
        if(file.gcount() != static_cast<std::streamsize>(kdfSalt.size())) {
            std::cerr << "Incomplete shuffle KDF salt in " << fileName << std::endl;
            return 1;
        }

        if(!args.use_keyfile) {
            std::cout << "Password for file " << fileName << ": " << std::flush;
            if(!readTerminalPassword(password)) {
                std::cerr << "Unable to read password" << std::endl;
                return 1;
            }
        }

        const size_t keyLength = args.use_keyfile ? keybuf.size() : password.size();
        const char* key = args.use_keyfile ? keybuf.data() : password.data();
        CipherSession cipher(keyLength, key, kdfSalt.size(),
                             reinterpret_cast<const char*>(kdfSalt.data()), iterations);

        std::array<uint8_t, BLOCK_SIZE> previousCiphertext{};
        std::array<uint8_t, BLOCK_SIZE> block{};
        auto readCipherBlock = [&]() {
            file.read(reinterpret_cast<char*>(block.data()), static_cast<std::streamsize>(block.size()));
            return file.gcount() == static_cast<std::streamsize>(block.size());
        };

        std::vector<uint8_t> decryptedHeader(headerCiphertextSize);
        std::vector<uint8_t> decrypted;
        std::array<uint8_t, BLOCK_SIZE> headerSignature{};
        for(size_t headerBlock = 0; headerBlock < headerBlockCount; ++headerBlock) {
            if(!readCipherBlock()) {
                std::cerr << "Ciphertext is missing a complete encrypted header block in "
                          << fileName << std::endl;
                return 1;
            }
            decrypted = cipher.decryptBlock(
                BLOCK_SIZE, reinterpret_cast<const char*>(previousCiphertext.data()),
                block.size(), reinterpret_cast<const char*>(block.data()), headerBlock);
            if(decrypted.size() != BLOCK_SIZE) {
                std::cerr << "Invalid encrypted header block in " << fileName << std::endl;
                return 1;
            }
            std::copy(decrypted.begin(), decrypted.end(),
                      decryptedHeader.begin() + headerBlock * BLOCK_SIZE);
            if(headerBlock == 0) {
                cipher.setFileContext(block.size(), reinterpret_cast<const char*>(block.data()));
                std::copy(block.begin(), block.end(), headerSignature.begin());
            }
            previousCiphertext = block;
        }

        std::uint64_t plaintextLength = 0;
        if(!shuffle_file_format::decodeHeader(decryptedHeader.data(), decryptedHeader.size(),
                                              BLOCK_SIZE, plaintextLength)) {
            std::cerr << "Unsupported, incorrect-password, or corrupt encrypted header in "
                      << fileName << std::endl;
            return 1;
        }

        if(args.verbosity >= 1) {
            std::cout << "Encrypted Header Signature:";
            for(const auto byte : headerSignature) {
                std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2)
                          << (static_cast<unsigned int>(byte) & 255U);
            }
            std::cout << std::dec << std::endl;
        }

        const std::uint64_t payloadBlockCount = plaintextLength == 0
            ? 0 : ((plaintextLength - 1) / BLOCK_SIZE) + 1;
        const std::uint64_t fixedLength = kdfSalt.size() + headerCiphertextSize;
        if(payloadBlockCount > (std::numeric_limits<std::uint64_t>::max() - fixedLength) / BLOCK_SIZE) {
            std::cerr << "Declared plaintext length overflows the file format in " << fileName << std::endl;
            return 1;
        }
        const std::uint64_t expectedCiphertextLength = fixedLength + payloadBlockCount * BLOCK_SIZE;
        if(ciphertextLength != expectedCiphertextLength) {
            std::cerr << "Ciphertext length does not match its encrypted length field in " << fileName << std::endl;
            return 1;
        }

        std::fstream outfile(fileName + ".dec", std::fstream::out | std::fstream::binary);
        if(!outfile.is_open()) {
            std::cerr << "Unable to open output for " << fileName << std::endl;
            return 1;
        }

        std::uint64_t remaining = plaintextLength;
        std::uint64_t blockIndex = headerBlockCount;
        while(remaining != 0) {
            if(!readCipherBlock()) {
                std::cerr << "Incomplete ciphertext block in " << fileName << std::endl;
                return 1;
            }
            decrypted = cipher.decryptBlock(BLOCK_SIZE,
                                            reinterpret_cast<const char*>(previousCiphertext.data()),
                                            block.size(), reinterpret_cast<const char*>(block.data()),
                                            blockIndex++);
            const size_t outputLength = static_cast<size_t>(std::min<std::uint64_t>(remaining, BLOCK_SIZE));
            outfile.write(reinterpret_cast<const char*>(decrypted.data()),
                          static_cast<std::streamsize>(outputLength));
            previousCiphertext = block;
            remaining -= outputLength;
        }

        if(!outfile) {
            std::cerr << "Unable to finish decryption for " << fileName << std::endl;
            return 1;
        }
        if(!args.use_keyfile) std::fill(password.begin(), password.end(), '\0');
    }

    return 0;
}

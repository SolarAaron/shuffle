// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include "args.hpp"
#include "file_format.hpp"
#include "secure_random.hpp"
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

    const bool defaultIterations = args.iterations == 0;
    const size_t iterations = defaultIterations
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
            std::cerr << "Unable to determine input size for " << fileName << std::endl;
            return 1;
        }
        const std::streamoff fileLength = static_cast<std::streamoff>(endPosition);
        if(fileLength < 0) {
            std::cerr << "Invalid input size for " << fileName << std::endl;
            return 1;
        }
        file.seekg(0, std::ios::beg);
        if(!file) {
            std::cerr << "Unable to rewind input " << fileName << std::endl;
            return 1;
        }
        const auto plaintextLength = static_cast<std::uint64_t>(fileLength);

        const std::string outputName = std::string(fileName) + '.' + std::string(CIPHER_NAME) +
            (defaultIterations ? std::string("") : (std::string(".") + std::to_string(iterations))) + ".sfl";
        std::fstream outfile(outputName, std::fstream::out | std::fstream::binary);
        if(!outfile.is_open()) {
            std::cerr << "Unable to open output for " << fileName << std::endl;
            return 1;
        }

        if(!args.use_keyfile) {
            std::cout << "Password for file " << fileName << ": " << std::flush;
            if(!readTerminalPassword(password)) {
                std::cerr << "Unable to read password" << std::endl;
                return 1;
            }
        }

        std::array<uint8_t, BLOCK_SIZE> kdfSalt{};
        std::array<char, BLOCK_SIZE> previousCiphertext{};
        std::array<char, BLOCK_SIZE> block{};
        std::array<uint8_t, BLOCK_SIZE> headerSignature{};
        try {
            secureRandomBytes(kdfSalt.data(), kdfSalt.size());
        } catch(const std::exception& error) {
            std::cerr << "Unable to generate file randomness: " << error.what() << std::endl;
            return 1;
        }

        outfile.write(reinterpret_cast<const char*>(kdfSalt.data()),
                      static_cast<std::streamsize>(kdfSalt.size()));
        if(!outfile) {
            std::cerr << "Unable to write file salt for " << fileName << std::endl;
            return 1;
        }

        const size_t keyLength = args.use_keyfile ? keybuf.size() : password.size();
        const char* key = args.use_keyfile ? keybuf.data() : password.data();
        CipherSession cipher(keyLength, key, kdfSalt.size(),
                             reinterpret_cast<const char*>(kdfSalt.data()), iterations);

        const auto header = shuffle_file_format::encodeHeader(plaintextLength, BLOCK_SIZE);
        std::vector<uint8_t> encrypted;
        std::uint64_t blockIndex = 0;
        for(size_t offset = 0; offset < header.size(); offset += BLOCK_SIZE) {
            std::copy_n(reinterpret_cast<const char*>(header.data() + offset), BLOCK_SIZE, block.begin());
            encrypted = cipher.encryptBlock(BLOCK_SIZE, previousCiphertext.data(), BLOCK_SIZE,
                                            block.data(), blockIndex++);
            if(blockIndex == 1) {
                cipher.setFileContext(encrypted.size(), reinterpret_cast<const char*>(encrypted.data()));
                std::copy(encrypted.begin(), encrypted.end(), headerSignature.begin());
            }
            std::memcpy(previousCiphertext.data(), encrypted.data(), encrypted.size());
            outfile.write(reinterpret_cast<const char*>(encrypted.data()),
                          static_cast<std::streamsize>(encrypted.size()));
        }

        if(args.verbosity >= 1) {
            std::cout << "Encrypted Header Signature:";
            for(const uint8_t byte : headerSignature) {
                std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2)
                          << (static_cast<unsigned int>(byte) & 255U);
            }
            std::cout << std::dec << std::endl;
        }

        std::uint64_t remaining = plaintextLength;
        while(remaining >= BLOCK_SIZE) {
            file.read(block.data(), static_cast<std::streamsize>(BLOCK_SIZE));
            if(file.gcount() != static_cast<std::streamsize>(BLOCK_SIZE)) {
                std::cerr << "Input changed or could not be read completely: " << fileName << std::endl;
                return 1;
            }
            encrypted = cipher.encryptBlock(BLOCK_SIZE, previousCiphertext.data(), BLOCK_SIZE,
                                            block.data(), blockIndex++);
            std::memcpy(previousCiphertext.data(), encrypted.data(), encrypted.size());
            outfile.write(reinterpret_cast<const char*>(encrypted.data()),
                          static_cast<std::streamsize>(encrypted.size()));
            remaining -= BLOCK_SIZE;
        }

        if(remaining != 0) {
            const auto mask = cipher.paddingMask(BLOCK_SIZE, previousCiphertext.data(), blockIndex);
            std::copy(mask.begin(), mask.end(), reinterpret_cast<uint8_t*>(block.data()));
            file.read(block.data(), static_cast<std::streamsize>(remaining));
            if(file.gcount() != static_cast<std::streamsize>(remaining)) {
                std::cerr << "Input changed or could not be read completely: " << fileName << std::endl;
                return 1;
            }
            encrypted = cipher.encryptBlock(BLOCK_SIZE, previousCiphertext.data(), BLOCK_SIZE,
                                            block.data(), blockIndex++);
            outfile.write(reinterpret_cast<const char*>(encrypted.data()),
                          static_cast<std::streamsize>(encrypted.size()));
        }

        char extraByte = 0;
        if(file.get(extraByte)) {
            std::cerr << "Input changed while being encrypted: " << fileName << std::endl;
            return 1;
        }
        outfile.flush();
        if(!file.eof() || !outfile) {
            std::cerr << "Unable to finish encryption for " << fileName << std::endl;
            return 1;
        }

        if(!args.use_keyfile) std::fill(password.begin(), password.end(), '\0');
    }

    return 0;
}

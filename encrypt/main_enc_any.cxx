// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <ranges>
#include "args.hpp"
#include "slr.crypto.hpp"
#include "terminal_password.hpp"

#ifdef TRUNCATION
constexpr size_t cipherHashBits = TRUNCATION;
#else
constexpr size_t cipherHashBits = slr::crypto::VariantSize<HASH_DEFINITION>::bitCount;
#endif

int main(int argc, char** argv){
    std::string keybuf;

    auto args = Args().parse(argc, argv);

    if(args.fileNames.empty()){
        std::cerr << "Usage: " << argv[0] << " [-k keyfile] file(s)" << std::endl;
    } else {
        std::fstream rnd;
        std::istreambuf_iterator<char> rit, kit, eos;
        rnd.open("/dev/random", std::fstream::in | std::fstream::binary);
        if(!rnd.is_open()) {
            std::cerr << "Unable to open the system random source" << std::endl;
            return 1;
        }
        rit = std::istreambuf_iterator<char>(rnd.rdbuf());

        if(args.useKeyfile){
            std::fstream kst;
            for(const auto& keyfile_name: args.keyfileNames) {
                kit = std::istreambuf_iterator<char>(kst.rdbuf());
                kst.open(keyfile_name, std::fstream::in | std::fstream::binary);
                while(kit != eos) {
                    keybuf += *kit++;
                }
                kst.close();
            }
        }

        const bool default_iterations = args.iterations == 0;
        const size_t iterations = default_iterations
            ? slr::crypto::defaultShuffleIterations<HASH_DEFINITION>()
            : args.iterations;

        for(auto fname: args.fileNames) {
            std::string buf;
            std::string password;
            std::array<char, BLOCK_SIZE> prevBlock{}, block{};

            std::istreambuf_iterator<char> iit;
            std::string arg;
            std::fstream file;
            std::fstream outfile;

            file.open(fname, std::fstream::in | std::fstream::binary);
            outfile.open(std::string(fname) + '.' + std::string(CIPHER_NAME) + (default_iterations ? std::string("") : (std::string(".") + std::to_string(iterations))) + ".sfl",
                         std::fstream::out | std::fstream::binary);
            if(!file.is_open() || !outfile.is_open()) {
                std::cerr << "Unable to open input or output for " << fname << std::endl;
                return 1;
            }

            iit = std::istreambuf_iterator<char>(file.rdbuf());
            arg = fname;

            if(!args.useKeyfile){
                std::cout << "Password for file " << arg << ": " << std::flush;
                if(!readTerminalPassword(password)) {
                    std::cerr << "Unable to read password" << std::endl;
                    return 1;
                }
            }

            for(size_t b = 0; b < BLOCK_SIZE; b++){
                block[b] = *rit++;
            }

            //IV
            if(args.verbosity >= 1) {
                std::cout << "IV Signature:";
                for(size_t sigX = 0; sigX < BLOCK_SIZE; sigX++) {
                    std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2)
                              << (((uint16_t) block[sigX]) & 255);
                }
                std::cout << std::endl;
            }

            auto keylen = args.useKeyfile ? keybuf.size() : password.size();
            auto key = args.useKeyfile ? keybuf.data() : password.data();
            auto crypted =
                slr::crypto::shuffleEncryptTruncated<BLOCK_SIZE, cipherHashBits, HASH_DEFINITION>(
                    keylen, key, BLOCK_SIZE, prevBlock.data(), BLOCK_SIZE, block.data(), iterations);
            std::ranges::copy(crypted, prevBlock.begin());
            outfile.write(prevBlock.data(), BLOCK_SIZE);
            outfile.flush();

            while(iit != eos){
                buf += *iit++;

                if(buf.size() == BLOCK_SIZE){
                    std::ranges::copy(buf, block.begin());
                    crypted =
                        slr::crypto::shuffleEncryptTruncated<BLOCK_SIZE, cipherHashBits, HASH_DEFINITION>(
                            keylen, key, BLOCK_SIZE, prevBlock.data(), BLOCK_SIZE, block.data(), iterations);
                    std::ranges::copy(crypted, prevBlock.begin());
                    outfile.write(prevBlock.data(), BLOCK_SIZE);
                    outfile.flush();
                    buf.clear();
                }
            }

            if(!buf.empty()){
                crypted = slr::crypto::shuffleEncryptTruncated<BLOCK_SIZE, cipherHashBits, HASH_DEFINITION>(
                    keylen, key, BLOCK_SIZE, prevBlock.data(), BLOCK_SIZE, prevBlock.data(), iterations);
                std::ranges::copy(crypted, block.begin());
                std::ranges::copy(buf, block.begin());
                crypted = slr::crypto::shuffleEncryptTruncated<BLOCK_SIZE, cipherHashBits, HASH_DEFINITION>(
                    keylen, key, BLOCK_SIZE, prevBlock.data(), BLOCK_SIZE, block.data(), iterations);
                std::ranges::copy(crypted, prevBlock.begin());
                outfile.write(prevBlock.data(), BLOCK_SIZE);
                outfile.flush();
            }

            if(file.is_open()){
                file.close();
            }

            if(outfile.is_open()){
                outfile.close();
            }

            if(!args.useKeyfile){
                std::ranges::fill(password, '\0');
            }
        }

        if(rnd.is_open()){
            rnd.close();
        }
    }

    return 0;
}

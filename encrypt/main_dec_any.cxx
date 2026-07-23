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
        std::cerr << "Usage: " << argv[0] <<" [-k keyfile] file(s)" << std::endl;
    } else {
        std::fstream rnd;
        std::istreambuf_iterator<char> rit, kit, eos;
        rit = std::istreambuf_iterator<char>(rnd.rdbuf());
        rnd.open("/dev/random", std::fstream::in | std::fstream::binary);

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

        const size_t iterations = args.iterations == 0
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
            outfile.open(std::string(fname) + ".dec", std::fstream::out | std::fstream::binary);
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

            auto keylen = args.useKeyfile ? keybuf.size() : password.size();
            auto key = args.useKeyfile ? keybuf.data() : password.data();

            bool completeIv = true;
            for(size_t b = 0; b < BLOCK_SIZE; b++){
                if(iit == eos) {
                    completeIv = false;
                    break;
                }
                block[b] = *iit++;
            }
            if(!completeIv) {
                std::cerr << "Ciphertext is shorter than its IV block: " << fname << std::endl;
                return 1;
            }

            //IV
            auto decrypted =
                slr::crypto::shuffleDecryptTruncated<BLOCK_SIZE, cipherHashBits, HASH_DEFINITION>(
                    keylen, key, BLOCK_SIZE, prevBlock.data(), BLOCK_SIZE, block.data(), iterations);

            if(args.verbosity >= 1) {
                std::cout << "IV Signature:";
                for(auto sigB: decrypted) {
                    std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2) << (((uint16_t) sigB) & 255);
                }
                std::cout << std::endl;
            }
            std::ranges::copy(block, prevBlock.begin());

            while(iit != eos){
                buf += *iit++;

                if(buf.size() == BLOCK_SIZE){
                    std::ranges::copy(buf, block.begin());
                    decrypted =
                        slr::crypto::shuffleDecryptTruncated<BLOCK_SIZE, cipherHashBits, HASH_DEFINITION>(
                            keylen, key, BLOCK_SIZE, prevBlock.data(), BLOCK_SIZE, block.data(), iterations);

                    if(iit == eos){
                        break;
                    } else {
                        std::ranges::copy(block, prevBlock.begin());
                        outfile.write(reinterpret_cast<const char*>(decrypted.data()), BLOCK_SIZE);
                        outfile.flush();
                        buf.clear();
                    }
                }
            }

            if(buf.size() == BLOCK_SIZE){
                auto crypted =
                    slr::crypto::shuffleEncryptTruncated<BLOCK_SIZE, cipherHashBits, HASH_DEFINITION>(
                        keylen, key, BLOCK_SIZE, prevBlock.data(), BLOCK_SIZE, prevBlock.data(), iterations);
                size_t limit = BLOCK_SIZE;
                while(limit > 0 && crypted[limit - 1] == decrypted[limit - 1]) limit--;
                outfile.write(reinterpret_cast<const char*>(decrypted.data()), limit);
            } else if(!buf.empty()) {
                std::cerr << "Ciphertext ends with a partial block: " << fname << std::endl;
                return 1;
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
        };
    }

    return 0;
}

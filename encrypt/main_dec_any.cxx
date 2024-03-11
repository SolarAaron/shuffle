#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <cstring>
#include "args.hpp"
#include "slr.crypto.hpp"

int main(int argc, char** argv){
    std::string buf, keybuf;

    auto args = Args().parse(argc, argv);

    if(args.file_names.empty()){
        std::cerr << "Usage: " << argv[0] <<" [-k keyfile] file(s)" << std::endl;
    } else {
        std::fstream rnd;
        std::istreambuf_iterator<char> rit, kit, eos;
        rit = std::istreambuf_iterator<char>(rnd.rdbuf());
        rnd.open("/dev/random", std::fstream::in | std::fstream::binary);

        if(args.use_keyfile){
            std::fstream kst;
            for(const auto& keyfile_name: args.keyfile_names) {
                kit = std::istreambuf_iterator<char>(kst.rdbuf());
                kst.open(keyfile_name, std::fstream::in | std::fstream::binary);
                while(kit != eos) {
                    keybuf += *kit++;
                }
                kst.close();
            }
        }

        for(auto fname: args.file_names) {
            char* password;
            auto prevBlock = new char[BLOCK_SIZE], block = new char[BLOCK_SIZE];

            std::istreambuf_iterator<char> iit;
            std::string arg;
            std::fstream file;
            std::fstream outfile;

            file.open(fname, std::fstream::in | std::fstream::binary);
            outfile.open(std::string(fname) + ".dec", std::fstream::out | std::fstream::binary);

            iit = std::istreambuf_iterator<char>(file.rdbuf());
            arg = fname;

            if(!args.use_keyfile){
                password = new char[256];
                std::cout << "Password for file " << arg << ": " << std::flush;
                std::cin >> password;
            }

            auto keylen = args.use_keyfile ? keybuf.size() : strlen(password);
            auto key = args.use_keyfile ? keybuf.data() : password;

            for(size_t b = 0; b < BLOCK_SIZE; b++){
                block[b] = *iit++;
            }

            size_t iterations = args.iterations == 0 ? slr::crypto::SC<HASH_DEFINITION>::value8 : args.iterations;

            //IV
            auto decrypted =
                slr::crypto::shuffleDecrypt<CIPHER_DEFINITION>(keylen, key, BLOCK_SIZE, prevBlock, BLOCK_SIZE, block,
                                                               iterations);

            if(args.verbosity >= 1) {
                std::cout << "IV Signature:";
                for(auto sigB: decrypted) {
                    std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2) << (((uint16_t) sigB) & 255);
                }
                std::cout << std::endl;
            }
            memcpy(prevBlock, block, BLOCK_SIZE);

            while(iit != eos){
                buf += *iit++;

                if(buf.size() == BLOCK_SIZE){
                    memcpy(block, buf.data(), BLOCK_SIZE);
                    decrypted =
                        slr::crypto::shuffleDecrypt<CIPHER_DEFINITION>(keylen, key, BLOCK_SIZE, prevBlock, BLOCK_SIZE,
                                                                       block, iterations);

                    if(iit == eos){
                        break;
                    } else {
                        memcpy(prevBlock, block, BLOCK_SIZE);
                        outfile.write(reinterpret_cast<const char*>(decrypted.data()), BLOCK_SIZE);
                        outfile.flush();
                        buf.clear();
                    }
                }
            }

            if(!buf.empty()){
                auto crypted =
                    slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(keylen, key, BLOCK_SIZE, prevBlock, BLOCK_SIZE,
                                                                   prevBlock, iterations);
                size_t limit = BLOCK_SIZE;
                while(crypted[limit - 1] == decrypted[limit - 1]) limit--;
                outfile.write(reinterpret_cast<const char*>(decrypted.data()), limit);
            }

            if(file.is_open()){
                file.close();
            }

            if(outfile.is_open()){
                outfile.close();
            }

            if(!args.use_keyfile){
                memset(password, 0, 256);
                delete[] password;
            }
        };
    }

    return 0;
}
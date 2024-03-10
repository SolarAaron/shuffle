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
            outfile.open(std::string(fname) + ".sfl", std::fstream::out | std::fstream::binary);

            iit = std::istreambuf_iterator<char>(file.rdbuf());
            arg = fname;

            if(!args.use_keyfile){
                password = new char[256];
                std::cout << "Password for file " << arg << ": " << std::flush;
                std::cin >> password;
            }

            for(size_t b = 0; b < BLOCK_SIZE; b++){
                block[b] = *rit++;
            }

            size_t iterations = args.iterations == 0 ? slr::crypto::SC<HASH_DEFINITION>::value8 : args.iterations;

            //IV
            std::cout << "IV Signature:";
            for(size_t sigX = 0; sigX < BLOCK_SIZE; sigX++){
                std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2) << (((uint16_t) block[sigX]) & 255);
            }
            std::cout << std::endl;

            auto keylen = args.use_keyfile ? keybuf.size() : strlen(password);
            auto key = args.use_keyfile ? keybuf.data() : password;
            auto crypted =
                slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(keylen, key, BLOCK_SIZE, prevBlock, BLOCK_SIZE, block,
                                                               iterations);
            memcpy(prevBlock, crypted.data(), crypted.size());
            outfile.write(prevBlock, BLOCK_SIZE);
            outfile.flush();

            while(iit != eos){
                buf += *iit++;

                if(buf.size() == BLOCK_SIZE){
                    memcpy(block, buf.data(), BLOCK_SIZE);
                    crypted =
                        slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(keylen, key, BLOCK_SIZE, prevBlock, BLOCK_SIZE,
                                                                       block, iterations);
                    memcpy(prevBlock, crypted.data(), crypted.size());
                    outfile.write(prevBlock, BLOCK_SIZE);
                    outfile.flush();
                    buf.clear();
                }
            }

            if(!buf.empty()){
                crypted = slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(keylen, key, BLOCK_SIZE, prevBlock, BLOCK_SIZE,
                                                                         prevBlock, iterations);
                memcpy(block, crypted.data(), crypted.size());
                memcpy(block, buf.data(), buf.size());
                crypted = slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(keylen, key, BLOCK_SIZE, prevBlock, BLOCK_SIZE,
                                                                         block, iterations);
                memcpy(prevBlock, crypted.data(), crypted.size());
                outfile.write(prevBlock, BLOCK_SIZE);
                outfile.flush();
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
        }

        if(rnd.is_open()){
            rnd.close();
        }
    }

    return 0;
}
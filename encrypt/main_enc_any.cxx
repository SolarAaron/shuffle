#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <cstring>
#include "slr.crypto.hpp"

int main(int argc, char** argv){
    std::string buf;
    int current = 1;

    if(argc == 1){
        std::cerr << "Usage: " << argv[0] << " file(s)" << std::endl;
    } else {
        std::fstream rnd;
        std::istreambuf_iterator<char> rit;
        rit = std::istreambuf_iterator<char>(rnd.rdbuf());
        rnd.open("/dev/random", std::fstream::in | std::fstream::binary);
        do{
            auto password = new char[256];
            auto prevBlock = new char[BLOCK_SIZE], block = new char[BLOCK_SIZE];

            std::istreambuf_iterator<char> eos;
            std::istreambuf_iterator<char> iit;
            std::string arg;
            std::fstream file;
            std::fstream outfile;

            file.open(argv[current], std::fstream::in | std::fstream::binary);
            outfile.open(std::string(argv[current]) + ".sfl", std::fstream::out | std::fstream::binary);

            iit = std::istreambuf_iterator<char>(file.rdbuf());
            arg = argv[current];

            std::cout << "Password for file " << arg << ": " << std::flush;
            std::cin >> password;

            for(size_t b = 0; b < BLOCK_SIZE; b++){
                block[b] = *rit++;
            }

            //IV
            std::cout << "IV Signature:";
            for(size_t sigX = 0; sigX < BLOCK_SIZE; sigX++){
                std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2) << (((uint16_t) block[sigX]) & 255);
            }
            std::cout << std::endl;

            auto crypted = slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(strlen(password), password, BLOCK_SIZE, prevBlock, BLOCK_SIZE, block);
            memcpy(prevBlock, crypted.data(), crypted.size());
            outfile.write(prevBlock, BLOCK_SIZE);
            outfile.flush();

            while(iit != eos){
                buf += *iit++;

                if(buf.size() == BLOCK_SIZE){
                    memcpy(block, buf.data(), BLOCK_SIZE);
                    crypted = slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(strlen(password), password, BLOCK_SIZE, prevBlock, BLOCK_SIZE, block);
                    memcpy(prevBlock, crypted.data(), crypted.size());
                    outfile.write(prevBlock, BLOCK_SIZE);
                    outfile.flush();
                    buf.clear();
                }
            }

            if(!buf.empty()){
                crypted = slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(strlen(password), password, BLOCK_SIZE, prevBlock, BLOCK_SIZE, prevBlock);
                memcpy(block, crypted.data(), crypted.size());
                memcpy(block, buf.data(), buf.size());
                crypted = slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(strlen(password), password, BLOCK_SIZE, prevBlock, BLOCK_SIZE, block);
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

            memset(password, 0, 256);
            delete[] password;
            current++;
        } while(current < argc);

        if(rnd.is_open()){
            rnd.close();
        }
    }

    return 0;
}
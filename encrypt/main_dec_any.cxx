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
        do{
            auto password = new char[256];
            auto prevBlock = new char[BLOCK_SIZE], block = new char[BLOCK_SIZE];

            std::istreambuf_iterator<char> eos;
            std::istreambuf_iterator<char> iit;
            std::string arg;
            std::fstream file;
            std::fstream outfile;

            file.open(argv[current], std::fstream::in | std::fstream::binary);
            outfile.open(std::string(argv[current]) + ".dec", std::fstream::out | std::fstream::binary);

            iit = std::istreambuf_iterator<char>(file.rdbuf());
            arg = argv[current];

            std::cout << "Password for file " << arg << ": " << std::flush;
            std::cin >> password;

            for(size_t b = 0; b < BLOCK_SIZE; b++){
                block[b] = *iit++;
            }

            //IV
            auto decrypted = slr::crypto::shuffleDecrypt<CIPHER_DEFINITION>(strlen(password), password, BLOCK_SIZE, prevBlock, BLOCK_SIZE, block);
            std::cout << "IV Signature:";
            for(auto sigB: decrypted){
                std::cout << ' ' << std::hex << std::setfill('0') << std::setw(2) << (((uint16_t) sigB) & 255);
            }
            std::cout << std::endl;
            memcpy(prevBlock, block, BLOCK_SIZE);

            while(iit != eos){
                buf += *iit++;

                if(buf.size() == BLOCK_SIZE){
                    memcpy(block, buf.data(), BLOCK_SIZE);
                    decrypted = slr::crypto::shuffleDecrypt<CIPHER_DEFINITION>(strlen(password), password, BLOCK_SIZE, prevBlock, BLOCK_SIZE, block);

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
                auto crypted = slr::crypto::shuffleEncrypt<CIPHER_DEFINITION>(strlen(password), password, BLOCK_SIZE, prevBlock,BLOCK_SIZE, prevBlock);
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

            memset(password, 0, 256);
            delete[] password;
            current++;
        } while(current < argc);
    }

    return 0;
}
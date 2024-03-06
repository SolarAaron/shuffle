#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include "slr.crypto.hpp"

int main(int argc, char** argv){
    std::string buf;
    int current = 2;
    do{
        std::istreambuf_iterator<char> eos;
        std::istreambuf_iterator<char> iit;
        std::string arg, password;
        std::fstream file;

        if(argc == 1){
            std::cerr << "Usage: " << argv[0] << " password [file(s)]" << std::endl;
        } else {
            password = argv[1];

            if(argc == 2){
                iit = std::istreambuf_iterator<char>(std::cin.rdbuf());
                arg = "-";
            } else {
                file.open(argv[ current ], std::fstream::in | std::fstream::binary);
                iit = std::istreambuf_iterator<char>(file.rdbuf());
                arg = argv[ current ];
            }

            while(iit != eos){
                buf += *iit++;
            }

            if(file.is_open()){
                file.close();
            }

            auto hash = slr::crypto::hmac<MAC_DEFINITION>(password.size(), password.c_str(), buf.size(), buf.c_str());
            std::for_each(hash.cbegin(), hash.cend(), [](uint8_t byte) -> void { std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)byte; });
            std::cout << " " << arg << std::endl;

            current++;
        }
    } while(current < argc);
    return 0;
}

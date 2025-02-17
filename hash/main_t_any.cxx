#include "crypto_ct.h"
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main(int argc, char** argv){
	std::string buf;
	int current = 1;
	do{
		std::istreambuf_iterator<char> eos;
		std::istreambuf_iterator<char> iit;
		std::string arg;
		std::fstream file;
		
		if(argc == 1){
			iit = std::istreambuf_iterator<char>(std::cin.rdbuf());
			arg = "-";
		} else {
			file.open(argv[current], std::fstream::in | std::fstream::binary);
			iit = std::istreambuf_iterator<char>(file.rdbuf());
			arg = argv[current];
		}

        poker_hash_sum const * const hash = init_poker_hash(HASH_SIGNATURE)();

        while(iit != eos){
            buf+=*iit++;

            if(buf.size() >= 100){
                hash_block(HASH_SIGNATURE)(hash, buf.c_str(), buf.size(), 0);
                buf.clear();
            }
        }

        if(file.is_open()){
            file.close();
        }

		hash_block(HASH_SIGNATURE)(hash, buf.c_str(), buf.size(), 0);
		char * hexHash = new char[get_hash_size(HASH_SIGNATURE)(hash)]();
		finish_hash_truncated(TRUNCATION, HASH_SIGNATURE)(hash, hexHash, 0);
		std::cout << hexHash << "  " << arg << std::endl;
		delete[] hexHash;
		
		current ++;
	} while(current < argc);
	return 0;
}

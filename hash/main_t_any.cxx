// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#include "slr.crypto.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main(int argc, char** argv){
	int current = 1;
	do {
		std::string buf;
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

        auto* hash = slr::crypto::hashBlock<HASH_DEFINITION>(0, nullptr);

        while(iit != eos){
            buf+=*iit++;

            if(buf.size() >= 100){
                slr::crypto::hashBlock<HASH_DEFINITION>(buf.size(), buf.data(), hash);
                buf.clear();
            }
        }

        if(file.is_open()){
            file.close();
        }

		slr::crypto::hashBlock<HASH_DEFINITION>(buf.size(), buf.data(), hash);
		auto* truncated = slr::crypto::truncate<
			slr::crypto::VariantSize<HASH_DEFINITION>::bitCount, TRUNCATION>(hash);
		const std::string hexHash = slr::crypto::finishHash(truncated);
		delete truncated;
		delete hash;
		std::cout << hexHash << "  " << arg << std::endl;
		
		current ++;
	} while(current < argc);
	return 0;
}

#include "slr.crypto.hpp"
#include "crypto_ct.h"

#include <cstring>

int finish_hash_truncated(TRUNCATION, HASH_SIGNATURE)(struct poker_hash_sum const * const hash, char * destination, size_t dest_offset){
    if(auto * casted = dynamic_cast<poker_hash_impl<HASH_DEFINITION> const * const>(hash)){
        auto trunc = slr::crypto::truncate<slr::crypto::SC<HASH_DEFINITION>::value8, TRUNCATION>(casted->hash);
        std::string hex = slr::crypto::finishHash(trunc);
        memcpy(destination + dest_offset, hex.c_str(), hex.size());
        delete casted;
        delete trunc;
        return 0;
    } else {
        return -1;
    }
}

int finish_hash_truncated64(TRUNCATION, HASH_SIGNATURE)(struct poker_hash_sum const * const hash, char * destination, size_t dest_offset){
    if(auto * casted = dynamic_cast<poker_hash_impl<HASH_DEFINITION> const * const>(hash)){
        auto trunc = slr::crypto::truncate<slr::crypto::SC<HASH_DEFINITION>::value8, TRUNCATION>(casted->hash);
        std::string hex = slr::crypto::finishHash64(trunc);
        memcpy(destination + dest_offset, hex.c_str(), hex.size());
        delete casted;
        delete trunc;
        return 0;
    } else {
        return -1;
    }
}
#include "slr.crypto.hpp"
#include "crypto_c.h"

#include <cstring>
#include <bitset>

struct poker_hash_sum const * init_poker_hash(HASH_SIGNATURE)(){
    auto * initial = new poker_hash_impl<HASH_DEFINITION>();
    initial->hash = slr::crypto::hashBlock<HASH_DEFINITION>(0, nullptr);
    return initial;
}

int hash_block(HASH_SIGNATURE)(struct poker_hash_sum const * const current, char const * buffer, size_t length, size_t offset){
    if(auto * casted = dynamic_cast<poker_hash_impl<HASH_DEFINITION> const * const>(current)){
        slr::crypto::hashBlock<HASH_DEFINITION>(length, buffer + offset, casted->hash);
        return 0;
    } else {
        return -1;
    }
}

size_t get_hash_size(HASH_SIGNATURE)(struct poker_hash_sum const * const hash){
    if(auto * casted = dynamic_cast<poker_hash_impl<HASH_DEFINITION> const * const>(hash)){
        return casted->size;
    } else {
        return -1;
    }
}

size_t get_hash64_size(HASH_SIGNATURE)(struct poker_hash_sum const * const hash){
    if(auto * casted = dynamic_cast<poker_hash_impl<HASH_DEFINITION> const * const>(hash)){
        return casted->size64;
    } else {
        return -1;
    }
}

int finish_hash(HASH_SIGNATURE)(struct poker_hash_sum const * const hash, char * destination, size_t dest_offset){
    if(auto * casted = dynamic_cast<poker_hash_impl<HASH_DEFINITION> const * const>(hash)){
        std::string hex = slr::crypto::finishHash(casted->hash);
        memcpy(destination + dest_offset, hex.c_str(), hex.size());
        delete casted;
        return 0;
    } else {
        return -1;
    }
}

int finish_hash64(HASH_SIGNATURE)(struct poker_hash_sum const * const hash, char * destination, size_t dest_offset){
    if(auto * casted = dynamic_cast<poker_hash_impl<HASH_DEFINITION> const * const>(hash)){
        std::string hex = slr::crypto::finishHash64(casted->hash);
        memcpy(destination + dest_offset, hex.c_str(), hex.size());
        delete casted;
        return 0;
    } else {
        return -1;
    }
}

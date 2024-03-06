#ifndef C_GUARD_SLR_CRYPTO
#define C_GUARD_SLR_CRYPTO

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
#define variant_append(a, b) a##b

#define init_poker_hash(variant) variant_append(init_poker_hash_, variant)
#define hash_block(variant) variant_append(hash_block_, variant)
#define get_hash_size(variant) variant_append(get_hash_size_, variant)
#define finish_hash(variant) variant_append(finish_hash_, variant)
#define get_hash64_size(variant) variant_append(get_hash64_size_, variant)
#define finish_hash64(variant) variant_append(finish_hash64_, variant)

struct poker_hash_sum {
    virtual ~poker_hash_sum();
};

#ifdef HASH_SIGNATURE

struct poker_hash_sum const *
init_poker_hash(HASH_SIGNATURE)();

int
hash_block(HASH_SIGNATURE)(struct poker_hash_sum const *const current, char const *buffer, size_t length, size_t offset);

size_t
get_hash_size(HASH_SIGNATURE)(struct poker_hash_sum const *const hash);

size_t
get_hash64_size(HASH_SIGNATURE)(struct poker_hash_sum const *const hash);

int
finish_hash(HASH_SIGNATURE)(struct poker_hash_sum const *const hash, char *destination, size_t offset);

int
finish_hash64(HASH_SIGNATURE)(struct poker_hash_sum const *const hash, char *destination, size_t offset);

#endif /*HASH_SIGNATURE*/

#ifdef __cplusplus
}
#endif

#endif /*C_GUARD_SLR_CRYPTO*/

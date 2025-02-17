#ifndef C_GUARD_SLR_CRYPTO_CT
#define C_GUARD_SLR_CRYPTO_CT

#include "crypto_c.h"

#ifdef __cplusplus
extern "C" {
#endif

#define truncation_append(a, t, b) a##T##t##_##b
#define finish_hash_truncated(truncation, variant) truncation_append(finish_hash_, truncation, variant)
#define finish_hash_truncated64(truncation, variant) truncation_append(finish_hash64_, truncation, variant)

#ifdef HASH_SIGNATURE
#ifdef TRUNCATION

int
finish_hash_truncated(TRUNCATION, HASH_SIGNATURE)(struct poker_hash_sum const *const hash, char *destination, size_t offset);

int
finish_hash_truncated64(TRUNCATION, HASH_SIGNATURE)(struct poker_hash_sum const *const hash, char *destination, size_t offset);

#endif /*TRUNCATION*/
#endif /*HASH_SIGNATURE*/

#ifdef __cplusplus
}
#endif

#endif //C_GUARD_SLR_CRYPTO_CT

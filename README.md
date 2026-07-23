<!--
SPDX-FileCopyrightText: 2024-2026 Aaron Torres
SPDX-License-Identifier: MIT
-->

# Shuffle

Shuffle is a C++20 implementation of the configurable Poker hash, HMAC and
PBKDF2 constructions, together with block-oriented `shuffle` encryption and
decryption tools. A generated C API library exposes the same configured
variants.

> [!WARNING]
> Poker is an experimental hash construction, not a standardized or
> independently reviewed cryptographic primitive. Do not use it in place of a
> well-established cryptographic library for security-critical data. Small
> variants and truncated digests have correspondingly small security margins.

## Configure and build

The project requires CMake and a compiler with C++20 support.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Building every default target can take substantial time. A single executable
and its dependencies can be built directly:

```sh
cmake --build build --target poker-2 shuffle-8_2 deshuffle-8_2
```

Install the executables, library and public headers with:

```sh
cmake --install build --prefix /usr/local
```

The main configuration variables are:

- `PRIMES`: positive integer variant factors; default `2;3;5`.
- `DEPTH`: multiplicative variant depths; default `1;2`.
- `TRUNCATION_MULTIPLIERS`: positive digest-width multipliers; default
  `5;6;7`. Values greater than 8 build successfully but repeat selected bits
  and therefore do not increase hash strength.
- `BUILD_SHARED_LIBS`: selects a shared rather than static C API library.
- `BUILD_TESTING`: enables the configured variant and C API tests.

For example, this configures a smaller development build:

```sh
cmake -S . -B build-small \
  -DPRIMES="2;3" \
  -DDEPTH=1 \
  -DTRUNCATION_MULTIPLIERS="5;6" \
  -DCMAKE_BUILD_TYPE=Release
```

## Variant and executable names

A variant name lists its template factors with underscores. If their product
is `P`, the full Poker digest contains `8 * P * P` bits. For variant `2`, for
example, `P` is 2 and the full digest is 32 bits.

Generated executable names follow these patterns:

| Purpose | Full hash | Truncated hash |
| --- | --- | --- |
| Hex digest | `poker-V` | `poker-TN_V` |
| Base64 digest | `poker64-V` | `poker64-TN_V` |
| Encrypt | `shuffle-B_V` | `shuffle-TN_B_V` |
| Decrypt | `deshuffle-B_V` | `deshuffle-TN_B_V` |

`V` is the variant, `B` is the cipher block size in bytes, and `N` is the
truncated digest width in bits. With variant `2`, block size 8 and truncation
multiplier 5, the truncated cipher is `shuffle-T20_8_2` because
`5 * 2 * 2 = 20`.

Encryption and decryption must use matching block size, variant, truncation,
password or key material, and iteration count.

### Hash-core behavior

Poker accepts input a byte at a time. Each byte derives a constant-time
forward/reverse injection schedule and uses precomputed permutation mappings
for eight sequential, state-dependent transitions. Consequently, changing one
input bit still affects its own transition and every subsequent transition;
byte-level processing does not collapse the eight rounds into a weaker single round.
On AVX2-capable x86 processors, the permuted bit gathers are vectorized at
runtime; other targets use the output-equivalent portable scalar path. Define
`SLR_CRYPTO_DISABLE_AVX2` when compiling a consumer to force the scalar path.

## Poker hash command line

Hash one or more files with hexadecimal output:

```sh
build/build/poker-2 document.txt archive.bin
```

Hash standard input:

```sh
printf '%s' 'message' | build/build/poker-2
```

Use `poker64-2` for Base64 output, or a generated truncated executable such as
`poker-T20_2`.

## Shuffle encryption

Without `-k`, the tools securely prompt for a password without terminal echo:

```sh
build/build/shuffle-8_2 secret.txt
build/build/deshuffle-8_2 secret.txt.8_2.sfl
```

Encryption writes `secret.txt.8_2.sfl`. Decryption writes
`secret.txt.8_2.sfl.dec`. When the default iteration count is used, the
decryptor derives the same variant-dependent default, so no iteration count
needs to be supplied.

Use a key file instead of a password prompt:

```sh
build/build/shuffle-8_2 -k key.bin secret.txt
build/build/deshuffle-8_2 -k key.bin secret.txt.8_2.sfl
```

Multiple `-k` options concatenate key files in command-line order. A custom
iteration count must be supplied to both commands:

```sh
build/build/shuffle-8_2 -i 50 -k key.bin secret.txt
build/build/deshuffle-8_2 -i 50 -k key.bin secret.txt.8_2.50.sfl
```

Pass `-v` to display the IV signature. Each input file is processed separately.

Truncated shuffle variants work the same way:

```sh
build/build/shuffle-T20_8_2 -k key.bin secret.txt
build/build/deshuffle-T20_8_2 -k key.bin secret.txt.T20_8_2.sfl
```

## C++ API

The C++ API is template-based and provided by `include/slr.crypto.hpp`. The
following example computes the full variant-2 digest:

```cpp
#include <memory>
#include <string>
#include <bitset>
#include "slr.crypto.hpp"

int main() {
    const std::string message = "hello";
    using Digest = std::bitset<slr::crypto::VariantSize<2>::bitCount>;
    std::unique_ptr<Digest> digest(
        slr::crypto::hashBlock<2>(message.size(), message.data()));
    const std::string hexadecimal = slr::crypto::finishHash(digest.get());
}
```

Compile a header-only consumer with C++20 enabled:

```sh
c++ -std=c++20 -Iinclude example.cxx -o example
```

`hashBlock<X...>` also has a continuation overload for streaming data.
`hashBlockTruncated<T, X...>`, `hmac`, `pbkdf2`, `shuffleEncrypt` and
`shuffleDecrypt` provide the corresponding higher-level operations. Objects
returned as pointers by the hashing and truncation templates are owned by the
caller.

## C API

The shared `slrcrypto_c` library exports symbols for every variant, block size
and truncation configured at build time. Define `HASH_SIGNATURE` and, for
cipher/HMAC/PBKDF operations, `BLOCK_SIZE` before including `crypto_c.h`.
Include `crypto_ct.h` as well when using `TRUNCATION`.

```c
#define HASH_SIGNATURE 2
#include "crypto_c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    static const char message[] = "hello";
    const struct poker_hash_sum *hash = init_poker_hash(2)();
    if (!hash) {
        return 1;
    }
    size_t size = get_hash_size(2)(hash);
    char *output = calloc(size, 1);

    if (!output ||
        hash_block(2)(hash, message, sizeof(message) - 1, 0) != 0 ||
        finish_hash(2)(hash, output, 0) != 0) {
        free(output);
        return 1;
    }

    puts(output);
    free(output);
    return 0;
}
```

The `finish_hash` call consumes and destroys the opaque hash object. Allocate
the size reported by `get_hash_size` and zero-initialize the destination, as in
the example. Link against the generated library:

```sh
cc -Iinclude example.c -Lbuild/build -lslrcrypto_c -o example
```

At runtime, make the installed library discoverable through the platform's
normal shared-library search mechanism.

## License

Shuffle is available under the [MIT License](LICENSE).

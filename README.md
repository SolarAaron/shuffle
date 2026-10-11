<!-- SPDX-FileCopyrightText: 2024-2026 Aaron Torres -->
<!-- SPDX-License-Identifier: MIT -->

# Shuffle

Shuffle is a C++17 implementation of the Poker digest family and a block-oriented
file-encryption tool built on that digest. A generated C API library exposes the
configured hash, HMAC, PBKDF2 and one-block shuffle variants.

> [!WARNING]
> Poker and the Shuffle block transform are experimental constructions, not
> standardized or independently reviewed cryptographic primitives. Do not use
> them in place of a well-established cryptographic library for security-critical
> data. Small variants and truncated digests have correspondingly small security
> margins.

## Configure and build

The project requires CMake and a compiler with C++17 support. The default
configuration expands many variant combinations; a smaller development build is:

```sh
cmake -S . -B build-small \
  -DPRIMES=2 \
  -DDEPTH=1 \
  -DTRUNCATION_MULTIPLIERS=5 \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build-small --parallel
ctest --test-dir build-small --output-on-failure
```

Executables are placed in `build-small/build/`. To build only the command-line
encryptor and decryptor for one configured variant:

```sh
cmake --build build-small --target shuffle-8_2 deshuffle-8_2
```

Install the configured programs, C API library and public headers with:

```sh
cmake --install build-small --prefix /usr/local
```

The main configuration variables are `PRIMES` (default `2;3;5`), `DEPTH`
(default `1;2`) and `TRUNCATION_MULTIPLIERS` (default `5;6;7`). Multipliers
greater than 8 repeat selected bits and do not increase hash strength.
`BUILD_SHARED_LIBS` controls whether the C API library is shared or static.
`BUILD_TESTING` enables the configured variant and C API tests.
The `hmac-*` and `pbk-*` executables are build targets only; they are not
installed. Public headers are `include/slr.crypto.hpp`, `include/crypto_c.h`
and `include/crypto_ct.h`.

## Variant and executable names

A variant name lists its template factors with underscores. If their product is
`P`, the full digest contains `8 * P * P` bits. Generated executable names use
these patterns:

| Purpose | Full hash | Truncated hash |
| --- | --- | --- |
| Hex digest | `poker-V` | `poker-TN_V` |
| Base64 digest | `poker64-V` | `poker64-TN_V` |
| Encrypt | `shuffle-B_V` | `shuffle-TN_B_V` |
| Decrypt | `deshuffle-B_V` | `deshuffle-TN_B_V` |

Here `V` is the variant, `B` is the cipher block size in bytes, and `N` is the
truncated digest width in bits. For variant `2`, block size 8 and truncation
multiplier 5, `N` is `5 * 2 * 2 = 20`, so the encryptor is named
`shuffle-T20_8_2`.

### Hash-core behavior

#### Variant size and initial state

A variant is a compile-time list of positive factors `X...`. Let `P` be their
product. The digest state is `P²` bytes (`8P²` bits). For example, the variant
`2,3` has a 36-byte, 288-bit state.

Hashing starts from an all-zero state, but first absorbs an ASCII domain string
formed by writing each factor in hexadecimal followed by a comma, then writing the
state byte count in hexadecimal. The message bytes are absorbed after this tag.
Consequently, different variants have different initial inputs as well as different
state widths.

#### Byte absorption and round operation

`hashBlock<X...>(length, data)` creates a new state and absorbs the domain tag and
then the supplied bytes. The overload taking a running bitset continues an existing
state, so hashing successive chunks is equivalent to absorbing their concatenation
in order. There is no separate final padding stage in this implementation.

Each input byte causes eight state transitions. For transition `r` (0 through 7),
the byte supplies a two-bit injection made from bit `r` and its mirrored bit
`7-r`. The transition applies the existing `bitFiddler` permutation and its
one-position forward/backward neighbors. For every destination byte it adds the
corresponding source, forward, and backward bytes, propagating the carry to the
next byte. The output of one transition is the input to the next. The implementation
precomputes the bit permutation and byte/mask neighbor mappings, then processes the
state in packed bytes; this is an implementation of the existing transition order,
not a different digest construction.

The result is returned as a heap-allocated `std::bitset`; the C++ caller owns it and
must delete it. The C ABI wraps the state in an opaque `poker_hash_sum` handle.

#### Digest output and truncation

`finishHash` emits lowercase hexadecimal; `finishHash64` emits the standard
`A-Z a-z 0-9 + /` alphabet without `=` padding. Both emit bitset chunks from low
index to high index. Hexadecimal left-aligns its leading partial byte. Base64
right-aligns its leading partial six-bit group in the first character; output
length is rounded up to the next chunk.

`hashBlockTruncated<T, X...>` first computes the full digest. It selects output bit
`i` from full-digest position
`(i + ((popcount * i) mod fullBits)) mod fullBits`, where `popcount` is the number
of set bits in that digest. If `T` exceeds the full width, positions repeat. When
packed as bytes, truncated bit zero becomes the least-significant bit of output byte
zero; a final partial byte is zero-filled above the selected bits. These selection
and packing rules are part of the output format.

The right-aligned Base64 partial-group behavior is an intentional output change
from earlier revisions. It affects digest widths not divisible by six; complete
six-bit groups are unchanged.

## Poker hash command line

Hash one or more files with hexadecimal output:

```sh
build-small/build/poker-2 document.txt archive.bin
```

With no file arguments, the hash tools read standard input:

```sh
printf '%s' 'message' | build-small/build/poker-2
```

Use `poker64-2` for Base64 output, or a generated truncated executable such as
`poker-T20_2` or `poker64-T20_2`.

## Shuffle encryption

Without `-k`, the tools prompt for a password without terminal echo:

```sh
build-small/build/shuffle-8_2 secret.txt
build-small/build/deshuffle-8_2 secret.txt.8_2.sfl
```

Encryption writes `secret.txt.8_2.sfl`; decryption writes
`secret.txt.8_2.sfl.dec`. The default iteration count is derived from the hash
variant, so the matching decryptor can use its default as well. To use key files,
pass one or more `-k` options; their contents are concatenated in command-line
order:

```sh
build-small/build/shuffle-8_2 -k key.bin secret.txt
build-small/build/deshuffle-8_2 -k key.bin secret.txt.8_2.sfl
```

A custom iteration count must be supplied to both commands. `-v` displays the
encrypted header signature. Truncated targets use the same options and framing:

```sh
build-small/build/shuffle-8_2 -i 50 -k key.bin secret.txt
build-small/build/deshuffle-8_2 -i 50 -k key.bin secret.txt.8_2.50.sfl
build-small/build/shuffle-T20_8_2 -k key.bin secret.txt
build-small/build/deshuffle-T20_8_2 -k key.bin secret.txt.T20_8_2.sfl
```

Encryption and decryption must use matching block size, variant, truncation,
password or key material, and iteration count.

The file tools use a `TruncatedShuffleKdfContext`; a full-width target is the same
context with `T` equal to the full digest width. The context is created once per
file and reused for every block. It derives one per-file KDF key, precomputes its
HMAC pad states, and builds a substitution schedule before processing blocks.

### Per-file key and round material

1. The password is hashed to a `T`-bit Poker digest. Those bits determine the
   number and ordering of cipher passes.
2. The password and a versioned, length-delimited root salt are fed to
   `pbkdf2Truncated`. Its domain prefix is the ASCII string
   `SLR-SHUFFLE-KEYSCHEDULE`, followed by version byte `0x01`, 64-bit big-endian
   block size, factor count and factors, and (for a truncated target) the 64-bit
   truncation width. A length-prefixed `pbkdf2-root` label and a length-prefixed
   constructor salt follow. PBKDF2 returns `ceil(T/8)` bytes. Its HMAC block size
   is the larger of the cipher block size and that digest byte count. The command-
   line tools generate a fresh `BSize`-byte system-random constructor salt for
   every file and store it as the first, unencrypted field in the file. The
   encrypted header follows; its first ciphertext block supplies the per-file
   context.
3. HMAC inner and outer pad states are initialized once from that KDF key and
   reused by the round-material expander. Each expansion message is domain-bound
   to the variant and block size, the block index, the first encrypted header
   block, the previous ciphertext block, and a purpose (`ciphertext-block` or
   `padding-mask`).
   Integer fields and byte-string lengths are encoded as 64-bit big-endian values;
   byte strings are length-prefixed. The expansion message uses the same versioned
   domain prefix and a length-prefixed `context-bound-expand` label, followed by
   block index, file context, previous ciphertext, and purpose. An increasing
   64-bit big-endian counter is appended for each HMAC output. The resulting stream
   supplies `BSize * T` round bytes per block.
4. Starting with the identity permutation of all 256 byte values, the context
   builds one substitution table per password-digest bit. It shuffles the table
   with split count `(cumulativeSetBits mod 14) + 2` and records that cumulative
   count for the corresponding bit permutation.

The default iteration count is `max(1, floor(1024 / fullHashBits))`; an explicit
`-i` value overrides it. Decryption must use the same target variant and iteration
count used during encryption.

### Encrypting and decrypting a block

Encryption copies up to `BSize` input bytes into a zero-initialized block. For each
of the `T` passes, it XORs each byte with that pass's round byte, substitutes the
result through that pass's 256-entry table, emits each substituted byte least-
significant-bit first, and shuffles the resulting `BSize * 8` bits. The shuffled
bits are packed back into bytes for the next pass. The bit-shuffle split count is
`(cumulativeSetBits mod (floor(sqrt(8 * BSize)) - 2)) + 2`.

Decryption runs those passes in reverse: it reverses the bit shuffle, uses the
precomputed inverse substitution table for that pass, then XORs the matching round
byte. The round material is regenerated from the same per-file and per-block
context, so neither round bytes nor substitution tables are stored in the ciphertext.

### File format and size visibility

Version 4 files start with a fresh `BSize`-byte random PBKDF2 salt (one cipher
block), which must remain readable so the decryptor can derive the key. The next
bytes are the encrypted header: an eight-byte `SLRSHFL4` format marker followed by
the unsigned plaintext length as a 64-bit big-endian integer, padded with zeroes to
a whole number of `BSize` blocks. With the minimum supported `BSize` of 8, the
header takes two encrypted blocks; for `BSize >= 16`, it fits in one. The marker,
length, and padding are encrypted. The ciphertext of the first header block
supplies the expander's file context, and each later ciphertext block becomes the
previous-ciphertext input for the next block.

Payload blocks immediately follow the encrypted header, and every ciphertext
block is exactly `BSize` bytes. A partial final plaintext block is placed at the
front of a block initialized from a separately expanded `padding-mask`, then
encrypted normally. Decryption uses the recovered exact length to write only the
payload prefix; it no longer guesses length by comparing suffix bytes. The fresh
salt is the only unencrypted framing field. The marker is encrypted, so this
version does not identify itself before key derivation; versions 2 and 3 are not
accepted by this framing.

For plaintext length `n`, the ciphertext length is
`BSize + headerBytes + BSize * ceil(n / BSize)`, where
`headerBytes = BSize * ceil(16 / BSize)`; the payload term is zero for an empty
file. Thus the encrypted header hides the exact length field,
but total file size still identifies the payload block count. For nonempty inputs,
that leaves at most `BSize - 1` bytes of length ambiguity; empty input remains
distinguishable.

The encrypted header does not record the variant, truncation width, or iteration
count. Those must be selected consistently at decryption time. The command-line
encryptor writes `<input>.<cipher-name>[.<iterations>].sfl`; the decryptor writes
`<input>.dec`.
Passwords can be read interactively or supplied as one or more concatenated key
files with `-k`.

### Output-preserving implementation details

The following changes keep the existing digest, HMAC, PBKDF2, and per-block cipher
operations byte-for-byte equivalent for the same inputs. The fresh salt and
encrypted, padded header are intentional file-format changes described above.

| Operation | Implemented change | Preserved behavior |
| --- | --- | --- |
| `packBitsToBytes` front-inserted each byte | Pre-size the result and write each byte at its final index | Bitset index 0 still maps to bit 0 of byte 0 |
| `pbkdf2Truncated` rebuilt key normalization and pad hashes for every `U` | Prepare key and pad starting states once, then clone states per message | Same `U` chain, truncated digest packing, and XOR order |
| `decryptBlock` linearly searched each substitution table | Build an inverse table beside each forward table | Same forward table and reverse-pass order |
| The expander copied its fixed info vector for every counter | Reuse the message buffer and rewrite its final 8-byte counter | Same `info || counter` bytes and counter order |
| `hashByteInjections` recomputed eight bit pairs per input byte | Cache all 256 eight-injection sequences | Same low-bit/mirrored-bit pair for every byte |
| Shuffle helpers allocated a result vector on every pass | Add reusable-output helpers and reuse scratch vectors in cipher passes and schedule setup | Same reversed-interleaved-bucket permutation, including non-divisible lengths |
| Legacy `pbkdf2` retained every `U` vector before XORing | XOR each `U` into a digest-sized accumulator as it is produced | Same HMAC chain and accumulator bytes, including the current zero-iteration behavior |

Regression tests compare these paths with reference implementations of the former
operations, including byte packing, permutations, HMAC, both PBKDF2 forms, and
fixed full-width and truncated per-block cipher vectors from before these changes.

Changing the digest transition, truncation selection, encoding bit order, domain
labels, KDF counter encoding, substitution schedule, shuffle order, or file framing
is not output-preserving. Such changes require new compatibility vectors and, for
file encryption, a format/version distinction.

### Security and format limitations

The file format has no authentication tag, so decryption cannot reliably detect a
wrong password or tampering. The encrypted header is not authenticated; the file
size still reveals the payload length rounded to a block boundary (and whether it
is empty). The random salt and explicit encrypted length address salt reuse and
suffix ambiguity, but do not make this custom cipher a reviewed authenticated-
encryption construction. Because the salt is one block, `BSize == 8` provides only
64 random salt bits; collisions become a consideration around billions of files
encrypted with the same password and settings. Larger block sizes provide more
salt collision margin.

## C++ API

The template-based C++ API is provided by `include/slr.crypto.hpp`. This example
computes the full hexadecimal digest for variant `2`:

```cpp
#include <iostream>
#include <string>

#include "slr.crypto.hpp"

int main() {
    const std::string message = "hello";
    auto* digest = slr::crypto::hashBlock<2>(message.size(), message.data());
    std::cout << slr::crypto::finishHash(digest) << '\n';
    delete digest;
}
```

Compile a header-only consumer with C++17:

```sh
c++ -std=c++17 -Iinclude example.cxx -o example
```

`hashBlock<X...>` also has an overload for continuing an existing state, so
input can be hashed in chunks. `hashBlockTruncated<T, X...>`, `hmac`, `pbkdf2`,
`shuffleEncrypt` and `shuffleDecrypt` provide the corresponding higher-level
operations. Hashing and truncation functions that return pointers transfer
ownership to the caller.

## C API

The generated `slrcrypto_c` library exports the variants configured at build
time. Define `HASH_SIGNATURE` before including `crypto_c.h`; define `BLOCK_SIZE`
as well when using the HMAC, PBKDF2 or one-block shuffle functions. Include
`crypto_ct.h` for the configured truncated variants.

```c
#define HASH_SIGNATURE 2
#include "crypto_c.h"

#include <stdio.h>

int main(void) {
    static const char message[] = "hello";
    char output[9] = {0}; /* variant 2: 8 hex characters plus NUL */
    struct poker_hash_sum const *hash = init_poker_hash(2)();

    if (hash == NULL) {
        return 1;
    }
    if (hash_block(2)(hash, message, sizeof(message) - 1, 0) != 0) {
        (void) finish_hash(2)(hash, output, 0); /* also releases the handle */
        return 1;
    }
    if (finish_hash(2)(hash, output, 0) != 0) {
        return 1;
    }

    puts(output);
    return 0;
}
```

The buffer size reported by `get_hash_size(V)` includes space for a NUL byte;
zero-initialize the destination because `finish_hash` writes the digest bytes
without writing that terminator. `finish_hash` consumes and destroys the opaque
hash handle. Link against the generated library, for example:

```sh
cc -Iinclude example.c -Lbuild-small/build -lslrcrypto_c -o example
```

The C API also exposes HMAC, PBKDF2 and single-block shuffle functions. The
`crypto_ct.h` header adds the equivalent truncated-hash forms. The C shuffle
functions operate on one block; they do not implement the command-line file
framing described above.

## License

Shuffle is available under the [MIT License](LICENSE).

// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef GUARD_SLR_CRYPTO
#define GUARD_SLR_CRYPTO
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <bitset>
#include <iomanip>
#include <ranges>
#include <stdexcept>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <climits>
#include <cmath>

#if !defined(SLR_CRYPTO_DISABLE_AVX2) && \
    (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#include <immintrin.h>
#define SLR_CRYPTO_AVX2_DISPATCH 1
#endif

namespace slr{
    /**
     * C++ API for the Poker hash and shuffle encryption primitives.
     *
     * Public types use `UpperCamelCase`; functions and data members use
     * `lowerCamelCase`. Documented aliases and wrappers retain legacy names.
     */
    namespace crypto {
        /**
         * Converts an integer value from host byte order to network byte order.
         *
         * `T` must be a trivially copyable integer-like type. The conversion is
         * performed at compile time when the supplied value permits it.
         */
        template<typename T> constexpr T
        htonT(T value) noexcept {
            #if __BYTE_ORDER == __LITTLE_ENDIAN
            char* ptr = reinterpret_cast<char*>(&value);
            std::reverse(ptr, ptr + sizeof(T));
            #endif
            return value;
        }

        /**
         * Compile-time dimensions for a variant described by `Factors`.
         *
         * `byteCount` is the square of the product of all factors and `bitCount`
         * is the corresponding size in bits. Every factor must be positive.
         * `value` and `value8` retain the former member names for compatibility.
         */
        template<size_t Factor, size_t... Factors> struct VariantSize {
            enum {
                value = Factor * Factor * VariantSize<Factors...>::value,
                value8 = 8 * Factor * Factor * VariantSize<Factors...>::value
            };
            static constexpr size_t byteCount = value;
            static constexpr size_t bitCount = value8;
        };

        template<size_t Factor> struct VariantSize<Factor> {
            enum {
                value = Factor * Factor,
                value8 = 8 * Factor * Factor
            };
            static constexpr size_t byteCount = value;
            static constexpr size_t bitCount = value8;
        };

        /**
         * Returns the default PBKDF iteration count for a shuffle variant.
         *
         * One hash invocation already becomes more expensive as the variant's
         * bit width grows, so the iteration count is scaled inversely to that
         * width. This keeps the default encryption cost reasonable for large
         * variants while retaining at least one derivation pass. Encryptors and
         * decryptors must use this same value when no count is supplied.
         */
        template<size_t... X> constexpr size_t
        defaultShuffleIterations() noexcept {
            constexpr size_t targetWorkBits = 1024;
            constexpr size_t hashBits = VariantSize<X...>::value8;
            return hashBits < targetWorkBits ? targetWorkBits / hashBits : 1;
        }

        /**
         * Recursive bit-permutation engine.
         *
         * `S` and `Bs` are byte and bit dimensions respectively; `Ks`, `Kd`,
         * and `X` describe the recursive variant dimensions. Most callers
         * should use `permuteBits` instead of instantiating this type directly.
         */
        template<size_t S, size_t Bs, size_t Ks, size_t Kd = 1, size_t... X> class BitFiddler {
        public:
            /**
             * Re-splits `src` and recursively applies the remaining dimensions in `X`.
             *
             * The instantiation must satisfy `Bs * Ks * Ks == S * 8`. On the
             * first pass, `Bs` may be `S * 8` and `Ks` may be 1. `sink` and
             * `src` must refer to distinct objects.
             */
            static void
            bitwisePass(std::bitset<S * 8>* const sink, std::array<std::bitset<Bs>, Ks * Ks>* const src) {
                std::array<std::bitset<(S * 8) / (Kd * Kd)>, Kd * Kd> step;

                size_t dest = 0;

                for(auto it = src->cbegin(); it < src->cend(); ++it){
                    for(size_t bit = 0; bit < it->size(); bit++){
                        const size_t stepIndex = dest % step.size();
                        step[stepIndex] <<= 1;
                        step[stepIndex][0] = (*it)[(it->size() - 1) - bit];
                        dest++;
                    }

                    const size_t stepIndex = dest % step.size();
                    std::array<std::bitset<(S*8)/(Kd*Kd)>, 1> inner = {step[stepIndex]};
                    BitFiddler<S/(Kd*Kd), (S*8)/(Kd*Kd), 1, X...>::bitwisePass(&step[stepIndex], &inner);
                }

                // next iteration
                BitFiddler<S, (S * 8) / (Kd * Kd), Kd, X...>::bitwisePass(sink, &step);
            }
        };

        template<size_t S, size_t Bs, size_t Ks, size_t Kd> class BitFiddler<S, Bs, Ks, Kd> {
        public:
            /**
             * Joins `src` into `sink` after the final `Kd` split.
             * The instantiation must satisfy `Bs * Ks * Ks == S * 8`.
             */
            static void
            bitwisePass(std::bitset<S * 8>* const sink, std::array<std::bitset<Bs>, Ks * Ks>* const src) {
                std::array<std::bitset<(S * 8) / (Kd * Kd)>, Kd * Kd> step;

                size_t dest = 0;

                for(auto it = src->cbegin(); it < src->cend(); ++it){
                    for(size_t bit = 0; bit < it->size(); bit++){
                        const size_t stepIndex = dest % step.size();
                        step[stepIndex] <<= 1;
                        step[stepIndex][0] = (*it)[(it->size() - 1) - bit];
                        dest++;
                    }
                }

                for(; dest < S * 8; dest++) {
                    const size_t stepIndex = dest / ((S * 8) / (Kd * Kd));
                    step[stepIndex] <<= 1;
                    step[stepIndex][0] = (*src)[dest / Bs][dest % Bs];
                }

                for(auto it = step.cbegin() ; it != step.cend(); ++it){
                    for(size_t bit = 0; bit < it->size(); bit++){
                        (*sink) <<= 1;
                        (*sink)[0] = (*it)[(it->size() - 1) - bit];
                    }
                }
            }
        };

        /**
         * Returns the lazily initialized output-to-input mapping for variant `X`.
         * An entry equal to the bit count denotes an output bit that is always zero.
         */
        template<size_t... X>
        const std::array<size_t, VariantSize<X...>::value8>& bitwisePermutation() {
            constexpr size_t bitCount = VariantSize<X...>::value8;
            static const std::array<size_t, bitCount> permutation = [] {
                std::array<size_t, bitCount> encoded{};
                std::array<std::bitset<bitCount>, 1> source{};

                size_t labelBits = 0;
                for(size_t labels = bitCount; labels != 0; labels >>= 1) ++labelBits;
                for(size_t labelBit = 0; labelBit < labelBits; ++labelBit) {
                    source[0].reset();
                    for(size_t input = 0; input < bitCount; ++input) {
                        source[0][input] = ((input + 1) >> labelBit) & 1U;
                    }
                    std::bitset<bitCount> shuffled;
                    BitFiddler<VariantSize<X...>::value, bitCount, 1, X...>::bitwisePass(&shuffled, &source);
                    for(size_t output = 0; output < bitCount; ++output) {
                        encoded[output] |= static_cast<size_t>(shuffled[output]) << labelBit;
                    }
                }

                std::array<size_t, bitCount> result{};
                for(size_t output = 0; output < bitCount; ++output) {
                    result[output] = encoded[output] == 0 ? bitCount : encoded[output] - 1;
                }
                return result;
            }();
            return permutation;
        }

        /** @internal Predecoded byte and mask selecting one bit from a packed hash state. */
        struct HashBitSource {
            uint32_t byte;
            uint8_t mask;
        };

        /** @internal Source-bit mappings for the two shifted permutations in one hash pass. */
        template<size_t BitCount> struct HashTransitions {
            std::array<HashBitSource, BitCount> forward;
            std::array<HashBitSource, BitCount> backward;
        };

        /** @internal Precomputes the composed permutation/shift/permutation hash mappings. */
        template<size_t... X>
        const HashTransitions<VariantSize<X...>::value8>& hashTransitions() {
            constexpr size_t bitCount = VariantSize<X...>::value8;
            static_assert(VariantSize<X...>::value + 1 <= static_cast<size_t>(UINT32_MAX),
                          "hash state is too large for transition byte indices");
            static const HashTransitions<bitCount> transitions = [] {
                HashTransitions<bitCount> result{};
                const auto& permutation = bitwisePermutation<X...>();
                for(size_t output = 0; output < bitCount; ++output) {
                    const size_t shiftedSource = permutation[output];
                    const size_t forwardSource = shiftedSource == 0 || shiftedSource >= bitCount
                        ? bitCount : permutation[shiftedSource - 1];
                    const size_t backwardSource = shiftedSource + 1 >= bitCount
                        ? bitCount : permutation[shiftedSource + 1];
                    result.forward[output] = forwardSource < bitCount
                        ? HashBitSource{static_cast<uint32_t>(forwardSource / 8),
                                        static_cast<uint8_t>(1U << (forwardSource % 8))}
                        : HashBitSource{static_cast<uint32_t>(bitCount / 8), 1};
                    result.backward[output] = backwardSource < bitCount
                        ? HashBitSource{static_cast<uint32_t>(backwardSource / 8),
                                        static_cast<uint8_t>(1U << (backwardSource % 8))}
                        : HashBitSource{static_cast<uint32_t>(bitCount / 8 + 1), 1};
                }
                return result;
            }();
            return transitions;
        }

#ifdef SLR_CRYPTO_AVX2_DISPATCH
        /** SIMD-friendly source bytes and bit shifts for eight-output gathers. */
        template<size_t BitCount> struct alignas(32) HashVectorTransitions {
            alignas(32) std::array<uint32_t, BitCount> forwardByte;
            alignas(32) std::array<uint32_t, BitCount> backwardByte;
            alignas(32) std::array<uint32_t, BitCount> forwardShift;
            alignas(32) std::array<uint32_t, BitCount> backwardShift;
        };

        template<size_t... X>
        const HashVectorTransitions<VariantSize<X...>::value8>& hashVectorTransitions() {
            constexpr size_t bitCount = VariantSize<X...>::value8;
            static const HashVectorTransitions<bitCount> transitions = [] {
                HashVectorTransitions<bitCount> result{};
                const auto& scalar = hashTransitions<X...>();
                for(size_t output = 0; output < bitCount; ++output) {
                    result.forwardByte[output] = scalar.forward[output].byte;
                    result.backwardByte[output] = scalar.backward[output].byte;
                    result.forwardShift[output] = std::countr_zero(scalar.forward[output].mask);
                    result.backwardShift[output] = std::countr_zero(scalar.backward[output].mask);
                }
                return result;
            }();
            return transitions;
        }
#endif

        /** @internal Packed hash bytes, two injected-bit slots, and SIMD gather padding. */
        template<size_t... X>
        using PackedHashState = std::array<uint8_t, VariantSize<X...>::value + 5>;

        /** Derives all forward/reverse injected bits without secret-indexed lookups. */
        inline std::array<uint8_t, 8> hashByteInjections(uint8_t byte) noexcept {
            uint8_t reversed = static_cast<uint8_t>((byte >> 4) | (byte << 4));
            reversed = static_cast<uint8_t>(((reversed & 0xccU) >> 2) | ((reversed & 0x33U) << 2));
            reversed = static_cast<uint8_t>(((reversed & 0xaaU) >> 1) | ((reversed & 0x55U) << 1));
            std::array<uint8_t, 8> result{};
            for(size_t round = 0; round < result.size(); ++round) {
                result[round] = static_cast<uint8_t>(
                    ((byte >> round) & 1U) | (((reversed >> round) & 1U) << 1));
            }
            return result;
        }

        /** Applies one state-dependent Poker transition from `source` to `destination`. */
        template<size_t... X>
        inline void packedHashRound(PackedHashState<X...>& source,
                                    PackedHashState<X...>& destination,
                                    const HashTransitions<VariantSize<X...>::value8>& transitions,
                                    uint8_t injection) {
            constexpr size_t byteCount = VariantSize<X...>::value;
            source[byteCount] = injection & 1U;
            source[byteCount + 1] = (injection >> 1) & 1U;

            uint16_t bitsum = 0;
            for(size_t destinationByte = 0; destinationByte < byteCount; ++destinationByte) {
                uint8_t forward = 0, backward = 0;
                for(size_t destinationBit = 0; destinationBit < 8; ++destinationBit) {
                    const size_t output = destinationByte * 8 + destinationBit;
                    const auto forwardSource = transitions.forward[output];
                    const auto backwardSource = transitions.backward[output];
                    forward |= static_cast<uint8_t>(
                        (source[forwardSource.byte] & forwardSource.mask) != 0) << destinationBit;
                    backward |= static_cast<uint8_t>(
                        (source[backwardSource.byte] & backwardSource.mask) != 0) << destinationBit;
                }
                bitsum += source[destinationByte] + forward + backward;
                destination[destinationByte] = static_cast<uint8_t>(bitsum);
                bitsum >>= 8;
            }
        }

#ifdef SLR_CRYPTO_AVX2_DISPATCH
        /** Applies one Poker transition using AVX2 gathers for its permuted bits. */
        template<size_t... X>
        __attribute__((target("avx2")))
        inline void packedHashRoundAvx2(
            PackedHashState<X...>& source,
            PackedHashState<X...>& destination,
            const HashVectorTransitions<VariantSize<X...>::value8>& transitions,
            uint8_t injection) {
            constexpr size_t byteCount = VariantSize<X...>::value;
            source[byteCount] = injection & 1U;
            source[byteCount + 1] = (injection >> 1) & 1U;
            const int* base = reinterpret_cast<const int*>(source.data());
            uint16_t bitsum = 0;
            for(size_t destinationByte = 0; destinationByte < byteCount; ++destinationByte) {
                const size_t output = destinationByte * 8;
                const __m256i forwardIndices = _mm256_load_si256(
                    reinterpret_cast<const __m256i*>(transitions.forwardByte.data() + output));
                const __m256i backwardIndices = _mm256_load_si256(
                    reinterpret_cast<const __m256i*>(transitions.backwardByte.data() + output));
                const __m256i forwardShifts = _mm256_load_si256(
                    reinterpret_cast<const __m256i*>(transitions.forwardShift.data() + output));
                const __m256i backwardShifts = _mm256_load_si256(
                    reinterpret_cast<const __m256i*>(transitions.backwardShift.data() + output));

                __m256i forwardValues = _mm256_i32gather_epi32(base, forwardIndices, 1);
                __m256i backwardValues = _mm256_i32gather_epi32(base, backwardIndices, 1);
                forwardValues = _mm256_slli_epi32(
                    _mm256_srlv_epi32(forwardValues, forwardShifts), 31);
                backwardValues = _mm256_slli_epi32(
                    _mm256_srlv_epi32(backwardValues, backwardShifts), 31);
                const uint8_t forward = static_cast<uint8_t>(
                    _mm256_movemask_ps(_mm256_castsi256_ps(forwardValues)));
                const uint8_t backward = static_cast<uint8_t>(
                    _mm256_movemask_ps(_mm256_castsi256_ps(backwardValues)));

                bitsum += source[destinationByte] + forward + backward;
                destination[destinationByte] = static_cast<uint8_t>(bitsum);
                bitsum >>= 8;
            }
        }

        /** AVX2 implementation of the same eight dependent transitions per byte. */
        template<size_t... X>
        __attribute__((target("avx2")))
        void absorbPackedHashAvx2(size_t length, char const* buffer, PackedHashState<X...>& state) {
            PackedHashState<X...> scratch{};
            const auto& transitions = hashVectorTransitions<X...>();

            for(size_t i = 0; i < length; ++i) {
                const auto injections = hashByteInjections(static_cast<uint8_t>(buffer[i]));
                packedHashRoundAvx2<X...>(state, scratch, transitions, injections[0]);
                packedHashRoundAvx2<X...>(scratch, state, transitions, injections[1]);
                packedHashRoundAvx2<X...>(state, scratch, transitions, injections[2]);
                packedHashRoundAvx2<X...>(scratch, state, transitions, injections[3]);
                packedHashRoundAvx2<X...>(state, scratch, transitions, injections[4]);
                packedHashRoundAvx2<X...>(scratch, state, transitions, injections[5]);
                packedHashRoundAvx2<X...>(state, scratch, transitions, injections[6]);
                packedHashRoundAvx2<X...>(scratch, state, transitions, injections[7]);
            }
        }
#endif

        /** Absorbs each byte as its precomputed composition of eight sequential rounds. */
        template<size_t... X>
        void absorbPackedHash(size_t length, char const* buffer, PackedHashState<X...>& state) {
            if(!buffer) return;

#ifdef SLR_CRYPTO_AVX2_DISPATCH
            if(__builtin_cpu_supports("avx2")) {
                absorbPackedHashAvx2<X...>(length, buffer, state);
                return;
            }
#endif

            PackedHashState<X...> scratch{};
            const auto& transitions = hashTransitions<X...>();
            for(size_t i = 0; i < length; ++i) {
                const auto injections = hashByteInjections(static_cast<uint8_t>(buffer[i]));
                packedHashRound<X...>(state, scratch, transitions, injections[0]);
                packedHashRound<X...>(scratch, state, transitions, injections[1]);
                packedHashRound<X...>(state, scratch, transitions, injections[2]);
                packedHashRound<X...>(scratch, state, transitions, injections[3]);
                packedHashRound<X...>(state, scratch, transitions, injections[4]);
                packedHashRound<X...>(scratch, state, transitions, injections[5]);
                packedHashRound<X...>(state, scratch, transitions, injections[6]);
                packedHashRound<X...>(scratch, state, transitions, injections[7]);
            }
        }

        /** Applies the cached `BitFiddler` mapping for variant `X`. */
        template<size_t... X>
        std::bitset<VariantSize<X...>::value8> permuteBits(const std::bitset<VariantSize<X...>::value8>& source) {
            std::bitset<VariantSize<X...>::value8> result;
            if constexpr(sizeof...(X) > 0) {
                const auto& permutation = bitwisePermutation<X...>();
                for(size_t output = 0; output < result.size(); ++output) {
                    if(permutation[output] < result.size()) {
                        result[output] = source[permutation[output]];
                    }
                }
            } else {
                std::array<std::bitset<VariantSize<X...>::value8>, 1> input = {source};
                BitFiddler<VariantSize<X...>::value, VariantSize<X...>::value8, 1, X...>::bitwisePass(&result, &input);
            }
            return result;
        }

        /** Copies at most `R` bits beginning at `offset`; an out-of-range offset returns zero bits. */
        template<size_t X, size_t R> std::bitset<R> bitSubset(const std::bitset<X>& bits, size_t offset){
            std::bitset<R> result;

            if(offset >= X) return result;
            for(size_t i = 0; i < std::min(R, X - offset); i++){
                result[i] = bits[i + offset];
            }

            return result;
        }

        /**
         * Continues `running` with `length` bytes from `buffer` and returns `running`.
         *
         * `running` must be non-null. A null `buffer` is treated as an empty
         * block regardless of `length`. The caller retains ownership of both.
         */
        template<size_t... X> std::bitset<VariantSize<X...>::value8>* const hashBlock(size_t length, char const* buffer, std::bitset<VariantSize<X...>::value8>* const running) {
            constexpr size_t byteCount = VariantSize<X...>::value;
            if(buffer) {
                PackedHashState<X...> state{};
                for(size_t byte = 0; byte < byteCount; ++byte) {
                    for(size_t bit = 0; bit < 8; ++bit) {
                        state[byte] |= static_cast<uint8_t>((*running)[byte * 8 + bit]) << bit;
                    }
                }
                absorbPackedHash<X...>(length, buffer, state);

                for(size_t byte = 0; byte < byteCount; ++byte) {
                    for(size_t bit = 0; bit < 8; ++bit) {
                        (*running)[byte * 8 + bit] = (state[byte] >> bit) & 1U;
                    }
                }
            }
            return running;
        }

        /** Returns the cached packed variant-specific state used before message absorption. */
        template<size_t... X>
        const PackedHashState<X...>& initialPackedHashState() {
            static const PackedHashState<X...> initial = [] {
                PackedHashState<X...> state{};
                std::stringstream name;
                name << std::hex;
                using ilst = int[];
                (void) ilst{0, ((void) (name << X << ','), 0)...};
                name << VariantSize<X...>::value;
                const std::string seed = name.str();
                absorbPackedHash<X...>(seed.size(), seed.data(), state);
                return state;
            }();
            return initial;
        }

        /** Returns the cached bitset form of the variant-specific initial state. */
        template<size_t... X>
        const std::bitset<VariantSize<X...>::value8>& initialHashState() {
            static const std::bitset<VariantSize<X...>::value8> initial = [] {
                std::bitset<VariantSize<X...>::value8> state;
                const auto& packed = initialPackedHashState<X...>();
                for(size_t byte = 0; byte < VariantSize<X...>::value; ++byte) {
                    for(size_t bit = 0; bit < 8; ++bit) {
                        state[byte * 8 + bit] = (packed[byte] >> bit) & 1U;
                    }
                }
                return state;
            }();
            return initial;
        }

        /**
         * Creates a variant-seeded hash and processes the initial input block.
         * A null `buffer` is treated as empty. The caller owns the returned
         * bitset and must delete it.
         */
        template<size_t... X> std::bitset<VariantSize<X...>::value8>* const hashBlock(size_t length, char const* buffer) {
            auto* initial = new std::bitset<VariantSize<X...>::value8>(initialHashState<X...>());
            return hashBlock<X...>(length, buffer, initial);
        }

        /**
         * Creates a `T`-bit selection from `original`, wrapping every selected
         * source index modulo `S`. When `T` exceeds `S`, output bits repeat and
         * do not add entropy.
         * `original` must be non-null. The caller owns the returned bitset;
         * `original` is not modified or deleted.
         */
        template<size_t S, size_t T> std::bitset<T>* const truncate(std::bitset<S>* const original) {
            static_assert(T > 0, "a truncated hash must contain at least one bit");
            auto ret = new std::bitset<T>();

            size_t offset = original->count();
            for(size_t bit = 0; bit < T; bit++) {
                (*ret)[bit] = (*original)[(bit + ((offset * bit) % S)) % S];
            }

            return ret;
        }

        /**
         * Hashes `length` bytes and selects exactly `T` wrapping Poker bits.
         *
         * `T` is measured in bits and `X` contains the positive variant
         * factors. A null `buffer` is treated as empty. The caller owns the
         * returned bitset and must delete it.
         */
        template<size_t T, size_t... X> std::bitset<T>* const
        hashBlockTruncated(size_t length, char const* buffer) {
            constexpr size_t fullBits = VariantSize<X...>::value8;
            static_assert(T > 0, "a truncated hash must contain at least one bit");
            auto full = hashBlock<X...>(length, buffer);
            if constexpr(T == fullBits) {
                return full;
            } else {
                auto result = truncate<fullBits, T>(full);
                delete full;
                return result;
            }
        }

        /**
         * Converts a hash bitset to its existing low-chunk-first hexadecimal encoding.
         * `block` must be non-null and remains owned by the caller. The returned
         * string contains exactly `2 * ((S + 7) / 8)` characters.
         */
        template<size_t S> std::string
        finishHash(std::bitset<S>* const block) {
            static constexpr char digits[] = "0123456789abcdef";
            constexpr size_t chunkCount = (S + 7) / 8;
            std::string result(chunkCount * 2, '0');
            size_t source = 0;

            for(size_t chunk = 0; chunk < chunkCount; ++chunk) {
                const size_t width = (chunk == 0 && S % 8 != 0) ? S % 8 : 8;
                const size_t shift = 8 - width;
                uint8_t value = 0;
                for(size_t bit = 0; bit < width; ++bit) {
                    value |= static_cast<uint8_t>((*block)[source + bit]) << (shift + bit);
                }
                result[chunk * 2] = digits[value >> 4];
                result[chunk * 2 + 1] = digits[value & 0x0f];
                source += width;
            }

            return result;
        }

        /**
         * Converts a hash bitset to the library's unpadded, low-chunk-first Base64 encoding.
         * `block` must be non-null and remains owned by the caller. The returned
         * string contains exactly `(S + 5) / 6` characters and has no `=` padding.
         */
        template<size_t S> std::string finishHash64(std::bitset<S>* const block){
            static constexpr char alphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            constexpr size_t chunkCount = (S + 5) / 6;
            std::string result(chunkCount, 'A');
            size_t source = 0;

            for(size_t chunk = 0; chunk < chunkCount; ++chunk) {
                const size_t width = (chunk == 0 && S % 6 != 0) ? S % 6 : 6;
                const size_t shift = 6 - width;
                uint8_t value = 0;
                for(size_t bit = 0; bit < width; ++bit) {
                    value |= static_cast<uint8_t>((*block)[source + bit]) << (shift + bit);
                }
                result[chunk] = alphabet[value];
                source += width;
            }

            return result;
        }

        /**
         * Packs each consecutive group of up to eight bits into one byte,
         * least-significant bit first. `block` must be non-null and remains
         * owned by the caller. The result contains `(S + 7) / 8` bytes.
         */
        template<size_t S> std::vector<uint8_t>
        packBitsToBytes(std::bitset<S>* const block) {
            std::vector<uint8_t> ret((S + 7) / 8);

            for(size_t byte = 0; byte < ret.size(); ++byte) {
                uint8_t value = 0;
                for(size_t bit = 0; bit < std::min<size_t>(8, S - byte * 8); ++bit) {
                    value |= static_cast<uint8_t>((*block)[byte * 8 + bit]) << bit;
                }
                ret[byte] = value;
            }

            return ret;
        }

        /** Packs a completed full hash after applying poker truncation to `T` bits. */
        template<size_t T, size_t... X>
        std::vector<uint8_t> packTruncatedHash(std::bitset<VariantSize<X...>::value8>* const block) {
            constexpr size_t fullBits = VariantSize<X...>::value8;
            static_assert(T > 0, "invalid truncated hash width");
            if constexpr(T == fullBits) {
                return packBitsToBytes(block);
            } else {
                auto truncated = truncate<fullBits, T>(block);
                auto result = packBitsToBytes(truncated);
                delete truncated;
                return result;
            }
        }

        /** Packs a full or poker-truncated digest directly from its byte state. */
        template<size_t T, size_t... X>
        std::vector<uint8_t> packTruncatedHash(const PackedHashState<X...>& state) {
            constexpr size_t fullBits = VariantSize<X...>::value8;
            constexpr size_t fullBytes = VariantSize<X...>::value;
            static_assert(T > 0, "invalid truncated hash width");
            if constexpr(T == fullBits) {
                return std::vector<uint8_t>(state.begin(), state.begin() + fullBytes);
            } else {
                std::vector<uint8_t> result((T + 7) / 8);
                size_t offset = 0;
                for(size_t byte = 0; byte < fullBytes; ++byte) {
                    offset += std::popcount(state[byte]);
                }
                for(size_t bit = 0; bit < T; ++bit) {
                    const size_t source = (bit + ((offset * bit) % fullBits)) % fullBits;
                    result[bit / 8] |= static_cast<uint8_t>(
                        ((state[source / 8] >> (source % 8)) & 1U) << (bit % 8));
                }
                return result;
            }
        }

        /**
         * Builds reusable `Bs`-byte HMAC pads using a `T`-bit digest.
         *
         * `Bs` is measured in bytes and `T` in bits. `keyBuffer` must address
         * `keyLength` readable bytes. Both output vectors are replaced.
         */
        template<size_t Bs, size_t T, size_t... X>
        void prepareHmacPadsTruncated(size_t keyLength, char const* keyBuffer,
                                      std::vector<uint8_t>& innerKey, std::vector<uint8_t>& outerKey) {
            std::vector<uint8_t> keyBytes(Bs);

            if(keyLength > Bs){
                auto block = hashBlock<X...>(keyLength, keyBuffer);
                keyBytes = packTruncatedHash<T, X...>(block);
                delete block;
                keyBytes.resize(Bs);
            } else {
                std::ranges::copy_n(keyBuffer, keyLength, keyBytes.begin());
            }

            innerKey.resize(Bs);
            outerKey.resize(Bs);
            for(size_t byte = 0; byte < Bs; ++byte) {
                innerKey[byte] = keyBytes[byte] ^ 0x36;
                outerKey[byte] = keyBytes[byte] ^ 0x5c;
            }
        }

        /** Builds the reusable `Bs`-byte inner and outer pads for HMAC variant `X`. */
        template<size_t Bs, size_t... X>
        void prepareHmacPads(size_t keyLength, char const* keyBuffer,
                             std::vector<uint8_t>& innerKey, std::vector<uint8_t>& outerKey) {
            prepareHmacPadsTruncated<Bs, VariantSize<X...>::value8, X...>(
                keyLength, keyBuffer, innerKey, outerKey);
        }

        /** Hashes fixed HMAC pads once so repeated HMAC calls can clone their states. */
        template<size_t... X>
        void prepareHmacStates(const std::vector<uint8_t>& innerKey,
                               const std::vector<uint8_t>& outerKey,
                               PackedHashState<X...>& innerState,
                               PackedHashState<X...>& outerState) {
            innerState = initialPackedHashState<X...>();
            outerState = initialPackedHashState<X...>();
            absorbPackedHash<X...>(innerKey.size(), reinterpret_cast<const char*>(innerKey.data()), innerState);
            absorbPackedHash<X...>(outerKey.size(), reinterpret_cast<const char*>(outerKey.data()), outerState);
        }

        /** Computes a `T`-bit HMAC by cloning states that already contain its pads. */
        template<size_t T, size_t... X>
        std::vector<uint8_t> hmacWithStatesTruncated(
            const PackedHashState<X...>& innerState,
            const PackedHashState<X...>& outerState,
            size_t msgLength, char const* msgBuffer) {
            auto iblock = innerState;
            absorbPackedHash<X...>(msgLength, msgBuffer, iblock);
            const auto ibytes = packTruncatedHash<T, X...>(iblock);

            auto fblock = outerState;
            absorbPackedHash<X...>(ibytes.size(), reinterpret_cast<const char*>(ibytes.data()), fblock);
            return packTruncatedHash<T, X...>(fblock);
        }

        /** Computes a `T`-bit HMAC using previously prepared pads. */
        template<size_t T, size_t... X>
        std::vector<uint8_t> hmacWithPadsTruncated(const std::vector<uint8_t>& innerKey,
                                                   const std::vector<uint8_t>& outerKey,
                                                   size_t msgLength, char const* msgBuffer) {
            PackedHashState<X...> innerState{}, outerState{};
            prepareHmacStates<X...>(innerKey, outerKey, innerState, outerState);
            return hmacWithStatesTruncated<T, X...>(innerState, outerState, msgLength, msgBuffer);
        }

        /** Computes HMAC using pads previously produced by `prepareHmacPads`. */
        template<size_t... X>
        std::vector<uint8_t> hmacWithPads(const std::vector<uint8_t>& innerKey,
                                          const std::vector<uint8_t>& outerKey,
                                          size_t msgLength, char const* msgBuffer) {
            return hmacWithPadsTruncated<VariantSize<X...>::value8, X...>(
                innerKey, outerKey, msgLength, msgBuffer);
        }

        /**
         * Computes an HMAC with a `Bs`-byte block and hash variant `X`.
         * Both input buffers must address their corresponding byte lengths.
         * The result contains `VariantSize<X...>::value` bytes.
         */
        template<size_t Bs, size_t... X> std::vector<uint8_t> hmac(size_t keyLength, char const* keyBuffer, size_t msgLength, char const* msgBuffer){
            std::vector<uint8_t> innerKey, outerKey;
            prepareHmacPads<Bs, X...>(keyLength, keyBuffer, innerKey, outerKey);
            return hmacWithPads<X...>(innerKey, outerKey, msgLength, msgBuffer);
        }

        /**
         * Derives exactly `length` bytes using HMAC variant `X` and block size `Bs`.
         * `Bs` and `length` are measured in bytes and `T` in bits. Both input
         * buffers must address their corresponding byte lengths. `iterations`
         * must be positive. HMAC pads are prepared once and reused;
         * independent output blocks are computed concurrently for wide variants.
         */
        template<size_t Bs, size_t T, size_t... X> std::vector<uint8_t>
        pbkdf2Truncated(size_t passLength, char const* passBuffer, size_t saltLength,
                        char const* saltBuffer, int32_t iterations, size_t length) {
            constexpr size_t hashBytes = (T + 7) / 8;
            static_assert(T > 0, "invalid PBKDF digest width");
            if(iterations <= 0) throw std::invalid_argument("pbkdf2 requires at least one iteration");
            if(length != 0 && (length - 1) / hashBytes >= static_cast<size_t>(UINT32_MAX)) {
                throw std::length_error("pbkdf2 output exceeds its 32-bit block counter");
            }

            std::vector<uint8_t> res(length);
            std::vector<uint8_t> innerKey, outerKey;
            prepareHmacPadsTruncated<Bs, T, X...>(passLength, passBuffer, innerKey, outerKey);
            PackedHashState<X...> innerState{}, outerState{};
            prepareHmacStates<X...>(innerKey, outerKey, innerState, outerState);
            const size_t blockCount = (length + hashBytes - 1) / hashBytes;

            auto deriveBlock = [&](size_t blockIndex) {
                std::vector<uint8_t> initial_salt(saltLength + 4);

                std::ranges::copy_n(saltBuffer, saltLength, initial_salt.begin());
                const uint32_t counter = static_cast<uint32_t>(blockIndex + 1);
                initial_salt[saltLength] = (counter >> 24) & 0xFF;
                initial_salt[saltLength + 1] = (counter >> 16) & 0xFF;
                initial_salt[saltLength + 2] = (counter >> 8) & 0xFF;
                initial_salt[saltLength + 3] = counter & 0xFF;

                auto current = hmacWithStatesTruncated<T, X...>(
                    innerState, outerState, initial_salt.size(),
                    reinterpret_cast<const char*>(initial_salt.data()));
                std::vector<uint8_t> block = current;
                for(size_t hashIteration = 1; hashIteration < static_cast<size_t>(iterations); ++hashIteration){
                    current = hmacWithStatesTruncated<T, X...>(
                        innerState, outerState, current.size(),
                        reinterpret_cast<const char*>(current.data()));
                    for(size_t byte = 0; byte < block.size(); ++byte){
                        block[byte] ^= current[byte];
                    }
                }

                const size_t offset = blockIndex * hashBytes;
                std::ranges::copy_n(block.begin(), std::min(hashBytes, length - offset), res.begin() + offset);
            };

            if constexpr(VariantSize<X...>::value8 >= 512) {
                std::atomic_size_t nextBlock{0};
                const size_t hardwareThreads = std::max(1U, std::thread::hardware_concurrency());
                const size_t workerCount = std::min(blockCount, hardwareThreads);
                std::vector<std::jthread> workers;
                workers.reserve(workerCount);
                for(size_t worker = 0; worker < workerCount; ++worker) {
                    workers.emplace_back([&] {
                        for(;;) {
                            const size_t blockIndex = nextBlock.fetch_add(1, std::memory_order_relaxed);
                            if(blockIndex >= blockCount) break;
                            deriveBlock(blockIndex);
                        }
                    });
                }
            } else {
                for(size_t blockIndex = 0; blockIndex < blockCount; ++blockIndex) deriveBlock(blockIndex);
            }

            return res;
        }

        /**
         * Derives exactly `length` bytes using the full-width digest.
         * Buffer and iteration preconditions match `pbkdf2Truncated`.
         */
        template<size_t Bs, size_t... X> std::vector<uint8_t>
        pbkdf2(size_t passLength, char const* passBuffer, size_t saltLength,
               char const* saltBuffer, int32_t iterations, size_t length) {
            return pbkdf2Truncated<Bs, VariantSize<X...>::value8, X...>(
                passLength, passBuffer, saltLength, saltBuffer, iterations, length);
        }

        /** Shuffles into reversed interleaved buckets; throws if `splits` is zero. */
        template<typename T> std::vector<T> shuffleBlock(const std::vector<T>& source, size_t splits){
            if(splits == 0) throw std::invalid_argument("shuffleBlock requires at least one split");
            std::vector<T> result(source.size());
            size_t resultIndex = 0;

            const size_t bucketCount = std::min(splits, source.size());
            for(size_t bucket = 0; bucket < bucketCount; ++bucket){
                size_t index = bucket + ((source.size() - 1 - bucket) / splits) * splits;
                for(;;){
                    result[resultIndex++] = source[index];
                    if(index < splits) break;
                    index -= splits;
                }
            }

            return result;
        }

        /** Reverses `shuffleBlock`; throws if `splits` is zero. */
        template<typename T> std::vector<T> reverseShuffleBlock(const std::vector<T>& source, size_t splits){
            if(splits == 0) throw std::invalid_argument("reverseShuffleBlock requires at least one split");
            std::vector<T> result(source.size());
            size_t sourceIndex = 0;

            const size_t bucketCount = std::min(splits, source.size());
            for(size_t bucket = 0; bucket < bucketCount; ++bucket){
                size_t index = bucket + ((source.size() - 1 - bucket) / splits) * splits;
                for(;;){
                    result[index] = source[sourceIndex++];
                    if(index < splits) break;
                    index -= splits;
                }
            }

            return result;
        }

        /** Bitset equivalent of `shuffleBlock`; throws if `splits` is zero. */
        template<size_t S> std::bitset<S> shuffleBitBlock(const std::bitset<S>& source, size_t splits){
            if(splits == 0) throw std::invalid_argument("shuffleBitBlock requires at least one split");
            std::bitset<S> result;
            size_t resultIndex = 0;

            const size_t bucketCount = std::min(splits, S);
            for(size_t bucket = 0; bucket < bucketCount; ++bucket){
                size_t index = bucket + ((S - 1 - bucket) / splits) * splits;
                for(;;){
                    result[resultIndex++] = source[index];
                    if(index < splits) break;
                    index -= splits;
                }
            }

            return result;
        }

        /** Reverses `shuffleBitBlock`; throws if `splits` is zero. */
        template<size_t S> std::bitset<S> reverseShuffleBitBlock(const std::bitset<S>& source, size_t splits){
            if(splits == 0) throw std::invalid_argument("reverseShuffleBitBlock requires at least one split");
            std::bitset<S> result;
            size_t sourceIndex = 0;

            const size_t bucketCount = std::min(splits, S);
            for(size_t bucket = 0; bucket < bucketCount; ++bucket){
                size_t index = bucket + ((S - 1 - bucket) / splits) * splits;
                for(;;){
                    result[index] = source[sourceIndex++];
                    if(index < splits) break;
                    index -= splits;
                }
            }

            return result;
        }

        /** Fixed-size, allocation-free equivalent of `shuffleBlock`. */
        template<typename T, size_t S>
        std::array<T, S> shuffleArray(const std::array<T, S>& source, size_t splits) {
            if(splits == 0) throw std::invalid_argument("shuffleArray requires at least one split");
            std::array<T, S> result{};
            size_t resultIndex = 0;
            const size_t bucketCount = std::min(splits, S);
            for(size_t bucket = 0; bucket < bucketCount; ++bucket) {
                size_t index = bucket + ((S - 1 - bucket) / splits) * splits;
                for(;;) {
                    result[resultIndex++] = source[index];
                    if(index < splits) break;
                    index -= splits;
                }
            }
            return result;
        }

        /** Fixed-size, allocation-free equivalent of `reverseShuffleBlock`. */
        template<typename T, size_t S>
        std::array<T, S> reverseShuffleArray(const std::array<T, S>& source, size_t splits) {
            if(splits == 0) throw std::invalid_argument("reverseShuffleArray requires at least one split");
            std::array<T, S> result{};
            size_t sourceIndex = 0;
            const size_t bucketCount = std::min(splits, S);
            for(size_t bucket = 0; bucket < bucketCount; ++bucket) {
                size_t index = bucket + ((S - 1 - bucket) / splits) * splits;
                for(;;) {
                    result[index] = source[sourceIndex++];
                    if(index < splits) break;
                    index -= splits;
                }
            }
            return result;
        }

        /** Packs a byte-aligned bitset without allocating. */
        template<size_t ByteCount>
        std::array<uint8_t, ByteCount> packBitsToArray(const std::bitset<ByteCount * 8>& block) {
            std::array<uint8_t, ByteCount> result{};
            for(size_t byte = 0; byte < ByteCount; ++byte) {
                for(size_t bit = 0; bit < 8; ++bit) {
                    result[byte] |= static_cast<uint8_t>(block[byte * 8 + bit]) << bit;
                }
            }
            return result;
        }

        /**
         * Encrypts with a `T`-bit poker-truncated hash. `T` may equal the full
         * hash width. `BSize` is the returned size in bytes and `T` is in bits.
         * Password and salt buffers must address their stated byte lengths.
         * At most `BSize` input bytes are read; missing bytes are zero-filled.
         * `iterations` must be positive.
         */
        template<size_t BSize, size_t T, size_t... X> std::vector<uint8_t>
        shuffleEncryptTruncated(size_t passLength, char const* passBuffer, size_t saltLength,
                                char const* saltBuffer, size_t length, char const* buffer,
                                size_t iterations) {
            static_assert(BSize >= 2, "shuffle encryption requires a block size of at least two bytes");
            static_assert(T > 0, "invalid shuffle hash width");
            size_t sqBSizeM2 = std::sqrt(BSize * 8.0) - 2;
            std::bitset<BSize * 8> blockBits;
            std::array<uint8_t, BSize> blockBytes{};
            std::array<uint8_t, 1 << (sizeof(uint8_t) * CHAR_BIT)> shuffleSub{};
            auto key = hashBlockTruncated<T, X...>(passLength, passBuffer);
            auto roundBytes =
                pbkdf2Truncated<BSize, T, X...>(passLength, passBuffer, saltLength, saltBuffer,
                                                iterations, BSize * key->size());

            for(size_t sub = 0; sub < shuffleSub.size(); ++sub) {
                shuffleSub[sub] = static_cast<uint8_t>(sub);
            }
            if(buffer) {
                std::ranges::copy_n(buffer, std::min(length, BSize), blockBytes.begin());
            }

            size_t roundSplit = 0;

            for(size_t pass = 0; pass < key->size(); pass++){
                if ((*key)[pass]) roundSplit++;

                shuffleSub = shuffleArray(shuffleSub, (roundSplit % 14) + 2);

                const uint8_t* const round = roundBytes.data() + pass * BSize;
                for(size_t bytePos = 0; bytePos < BSize; bytePos++){
                    const uint8_t substituted = shuffleSub[round[bytePos] ^ blockBytes[bytePos]];

                    for(size_t bit = 0; bit < 8; ++bit){
                        blockBits[bytePos * 8 + bit] = (substituted >> bit) & 1U;
                    }
                }

                blockBits = shuffleBitBlock(blockBits, (roundSplit % sqBSizeM2) + 2);

                blockBytes = packBitsToArray<BSize>(blockBits);
            }

            delete key;

            return std::vector<uint8_t>(blockBytes.begin(), blockBytes.end());
        }

        /** Encrypts and returns one `BSize`-byte block using the full-width hash. */
        template<size_t BSize, size_t... X> std::vector<uint8_t>
        shuffleEncrypt(size_t passLength, char const* passBuffer, size_t saltLength, char const* saltBuffer,
                       size_t length, char const* buffer, size_t iterations) {
            return shuffleEncryptTruncated<BSize, VariantSize<X...>::value8, X...>(
                passLength, passBuffer, saltLength, saltBuffer, length, buffer, iterations);
        }

        /**
         * Decrypts with a `T`-bit poker-truncated hash. Parameters must match
         * those used by `shuffleEncryptTruncated`. Returns exactly `BSize`
         * bytes; at most `BSize` input bytes are read and missing bytes are zero-filled.
         */
        template<size_t BSize, size_t T, size_t... X> std::vector<uint8_t>
        shuffleDecryptTruncated(size_t passLength, char const* passBuffer, size_t saltLength,
                                char const* saltBuffer, size_t length, char const* buffer,
                                size_t iterations) {
            static_assert(BSize >= 2, "shuffle decryption requires a block size of at least two bytes");
            static_assert(T > 0, "invalid shuffle hash width");
            size_t sqBSizeM2 = std::sqrt(BSize * 8.0) - 2;
            std::bitset<BSize * 8> blockBits;
            std::array<uint8_t, BSize> blockBytes{};
            std::array<uint8_t, 1 << (sizeof(uint8_t) * CHAR_BIT)> shuffleSub{};
            auto key = hashBlockTruncated<T, X...>(passLength, passBuffer);
            auto roundBytes =
                pbkdf2Truncated<BSize, T, X...>(passLength, passBuffer, saltLength, saltBuffer,
                                                iterations, BSize * key->size());

            for(size_t sub = 0; sub < shuffleSub.size(); ++sub) {
                shuffleSub[sub] = static_cast<uint8_t>(sub);
            }
            if(buffer) {
                std::ranges::copy_n(buffer, std::min(length, BSize), blockBytes.begin());
            }

            size_t roundSplit = 0;

            for(size_t pass = 0; pass < key->size(); pass++){ // regenerate substitution schedule
                if ((*key)[pass]) roundSplit++;
                shuffleSub = shuffleArray(shuffleSub, (roundSplit % 14) + 2);
            }

            for(size_t pass = 0; pass < key->size(); pass++){
                size_t rpass = (key->size() - 1) - pass;

                for(size_t bytePos = 0; bytePos < BSize; bytePos++){
                    const uint8_t blockByte = blockBytes[bytePos];

                    for(size_t bit = 0; bit < 8; ++bit){
                        blockBits[bytePos * 8 + bit] = (blockByte >> bit) & 1U;
                    }
                }

                blockBits = reverseShuffleBitBlock(blockBits, (roundSplit % sqBSizeM2) + 2);

                blockBytes = packBitsToArray<BSize>(blockBits);

                std::array<uint8_t, 1 << (sizeof(uint8_t) * CHAR_BIT)> inverseSub{};
                for(size_t index = 0; index < shuffleSub.size(); ++index) {
                    inverseSub[shuffleSub[index]] = static_cast<uint8_t>(index);
                }
                const uint8_t* const round = roundBytes.data() + rpass * BSize;
                for(size_t bytePos = 0; bytePos < BSize; bytePos++){
                    blockBytes[bytePos] = inverseSub[blockBytes[bytePos]] ^ round[bytePos];
                }

                shuffleSub = reverseShuffleArray(shuffleSub, (roundSplit % 14) + 2);
                if ((*key)[rpass]) roundSplit--;
            }

            delete key;

            return std::vector<uint8_t>(blockBytes.begin(), blockBytes.end());
        }

        /** Decrypts and returns one `BSize`-byte block using the full-width hash. */
        template<size_t BSize, size_t... X> std::vector<uint8_t>
        shuffleDecrypt(size_t passLength, char const* passBuffer, size_t saltLength, char const* saltBuffer,
                       size_t length, char const* buffer, size_t iterations) {
            return shuffleDecryptTruncated<BSize, VariantSize<X...>::value8, X...>(
                passLength, passBuffer, saltLength, saltBuffer, length, buffer, iterations);
        }
    }
}
#ifdef SLR_CRYPTO_AVX2_DISPATCH
#undef SLR_CRYPTO_AVX2_DISPATCH
#endif
#endif /*GUARD_SLR_CRYPTO*/

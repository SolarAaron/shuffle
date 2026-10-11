// SPDX-FileCopyrightText: 2024-2026 Aaron Torres
// SPDX-License-Identifier: MIT

#ifndef GUARD_SLR_CRYPTO
#define GUARD_SLR_CRYPTO
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <array>
#include <bitset>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <climits>
#include <cmath>
#include <limits>
#include <stdexcept>

namespace slr{
    namespace crypto {
        namespace /* unnamed */ {
            template<typename T> constexpr T
            htonT(T value) noexcept {
                #if __BYTE_ORDER == __LITTLE_ENDIAN
                char* ptr = reinterpret_cast<char*>(&value);
                std::reverse(ptr, ptr + sizeof(T));
                #endif
                return value;
            }

            template<size_t S, size_t... X> struct SC {
                enum {
                    value = S * S * SC<X...>::value,
                    value8 = 8 * S * S * SC<X...>::value
                };
            };

            template<size_t S> struct SC<S> {
                enum {
                    value = S * S,
                    value8 = 8 * S * S
                };
            };

            template<size_t... X> constexpr size_t
            defaultShuffleIterations() noexcept {
                constexpr size_t targetWorkBits = 1024;
                constexpr size_t hashBits = SC<X...>::value8;
                return hashBits < targetWorkBits ? targetWorkBits / hashBits : 1;
            }
        }

        template<size_t S, size_t Bs, size_t Ks, size_t Kd = 1, size_t... X> class bitFiddler {
        public:
            /**
             * Re-splits the bitsets at src and passes them to the next iteration as specified in ...X
             * it should hold that B*K*K = S*8
             * The first pass may be B = S*8, K = 1, but the bitset in src must not be the same instance as sink
             * */
            static void
            bitwisePass(std::bitset<S * 8>* const sink, std::array<std::bitset<Bs>, Ks * Ks>* const src) {
                std::array<std::bitset<(S * 8) / (Kd * Kd)>, Kd * Kd> step;

                size_t dest = 0;

                for(auto it = src->cbegin(); it < src->cend(); ++it){
                    for(size_t bit = 0; bit < it->size(); bit++){
                        step.at(dest % step.size()) <<= 1;
                        step.at(dest % step.size())[0] = (*it)[(it->size() - 1) - bit];
                        dest++;
                    }

                    std::array<std::bitset<(S*8)/(Kd*Kd)>, 1> inner = {step.at(dest % step.size())};
                    bitFiddler<S/(Kd*Kd), (S*8)/(Kd*Kd), 1, X...>::bitwisePass(&step.at(dest % step.size()), &inner);
                }

                // next iteration
                bitFiddler<S, (S * 8) / (Kd * Kd), Kd, X...>::bitwisePass(sink, &step);
            }
        };

        template<size_t S, size_t Bs, size_t Ks, size_t Kd> class bitFiddler<S, Bs, Ks, Kd> {
        public:
            /**
             * Joins the bitsets at src into sink, as a final step after the D split
             * it should hold that B*K*K = S*8
             * */
            static void
            bitwisePass(std::bitset<S * 8>* const sink, std::array<std::bitset<Bs>, Ks * Ks>* const src) {
                std::array<std::bitset<(S * 8) / (Kd * Kd)>, Kd * Kd> step;

                size_t dest = 0;

                for(auto it = src->cbegin(); it < src->cend(); ++it){
                    for(size_t bit = 0; bit < it->size(); bit++){
                        step.at(dest % step.size()) <<= 1;
                        step.at(dest % step.size())[0] = (*it)[(it->size() - 1) - bit];
                        dest++;
                    }
                }

                for(; dest < S * 8; dest++) {
                    step.at(dest / ((S * 8) / (Kd * Kd))) <<= 1;
                    step.at(dest / ((S * 8) / (Kd * Kd)))[0] = src->at(dest / Bs)[dest % Bs];
                }

                for(auto it = step.cbegin() ; it != step.cend(); ++it){
                    for(size_t bit = 0; bit < it->size(); bit++){
                        (*sink) <<= 1;
                        (*sink)[0] = (*it)[(it->size() - 1) - bit];
                    }
                }
            }
        };

        /** Output-to-input bit mapping for the existing BitFiddler permutation. */
        template<size_t... X>
        const std::vector<size_t>& bitwisePermutation() {
            static const std::vector<size_t> permutation = [] {
                constexpr size_t bitCount = SC<X...>::value8;
                std::vector<size_t> encoded(bitCount);
                std::array<std::bitset<bitCount>, 1> source{};

                size_t labelBits = 0;
                for(size_t labels = bitCount; labels != 0; labels >>= 1) ++labelBits;
                for(size_t labelBit = 0; labelBit < labelBits; ++labelBit) {
                    source[0].reset();
                    for(size_t input = 0; input < bitCount; ++input) {
                        source[0][input] = ((input + 1) >> labelBit) & 1U;
                    }
                    std::bitset<bitCount> shuffled;
                    bitFiddler<SC<X...>::value, bitCount, 1, X...>::bitwisePass(&shuffled, &source);
                    for(size_t output = 0; output < bitCount; ++output) {
                        encoded[output] |= static_cast<size_t>(shuffled[output]) << labelBit;
                    }
                }

                std::vector<size_t> result(bitCount);
                for(size_t output = 0; output < bitCount; ++output) {
                    result[output] = encoded[output] == 0 ? bitCount : encoded[output] - 1;
                }
                return result;
            }();
            return permutation;
        }

        /** A predecoded source byte and mask for one permuted output bit. */
        struct HashBitSource {
            size_t byte;
            uint8_t mask;
        };

        /** Source mappings for both shifted permutations in one legacy hash round. */
        struct HashTransitions {
            std::vector<HashBitSource> forward;
            std::vector<HashBitSource> backward;
        };

        /** Composes the existing permutation, one-bit shift, and permutation. */
        template<size_t... X>
        const HashTransitions& hashTransitions() {
            static const HashTransitions transitions = [] {
                constexpr size_t bitCount = SC<X...>::value8;
                HashTransitions result{std::vector<HashBitSource>(bitCount),
                                       std::vector<HashBitSource>(bitCount)};
                const auto& permutation = bitwisePermutation<X...>();
                for(size_t output = 0; output < bitCount; ++output) {
                    const size_t shiftedSource = permutation[output];
                    const size_t forwardSource = shiftedSource == 0 || shiftedSource >= bitCount
                        ? bitCount : permutation[shiftedSource - 1];
                    const size_t backwardSource = shiftedSource + 1 >= bitCount
                        ? bitCount : permutation[shiftedSource + 1];
                    result.forward[output] = forwardSource < bitCount
                        ? HashBitSource{forwardSource / 8,
                                        static_cast<uint8_t>(1U << (forwardSource % 8))}
                        : HashBitSource{bitCount / 8, 1};
                    result.backward[output] = backwardSource < bitCount
                        ? HashBitSource{backwardSource / 8,
                                        static_cast<uint8_t>(1U << (backwardSource % 8))}
                        : HashBitSource{bitCount / 8 + 1, 1};
                }
                return result;
            }();
            return transitions;
        }

        template<size_t... X>
        using PackedHashState = std::array<uint8_t, SC<X...>::value + 2>;

        using HashByteInjection = std::array<uint8_t, 8>;

        inline const std::array<HashByteInjection, 1U << CHAR_BIT>& hashByteInjectionTable() noexcept {
            static const auto table = [] {
                std::array<HashByteInjection, 1U << CHAR_BIT> result{};
                for(size_t value = 0; value < result.size(); ++value) {
                    for(size_t round = 0; round < result[value].size(); ++round) {
                        const auto byte = static_cast<uint8_t>(value);
                        result[value][round] = static_cast<uint8_t>(
                            ((byte >> round) & 1U) | (((byte >> (7 - round)) & 1U) << 1));
                    }
                }
                return result;
            }();
            return table;
        }

        inline const HashByteInjection& hashByteInjections(uint8_t byte) noexcept {
            return hashByteInjectionTable()[byte];
        }

        template<size_t... X>
        inline void packedHashRound(PackedHashState<X...>& source,
                                    PackedHashState<X...>& destination,
                                    const HashTransitions& transitions,
                                    uint8_t injection) {
            constexpr size_t byteCount = SC<X...>::value;
            source[byteCount] = injection & 1U;
            source[byteCount + 1] = (injection >> 1) & 1U;

            uint16_t bitsum = 0;
            for(size_t destinationByte = 0; destinationByte < byteCount; ++destinationByte) {
                uint8_t forward = 0;
                uint8_t backward = 0;
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

        template<size_t... X>
        void absorbPackedHash(size_t length, char const* buffer, PackedHashState<X...>& state) {
            if(!buffer) return;

            PackedHashState<X...> scratch{};
            const auto& transitions = hashTransitions<X...>();
            for(size_t byteIndex = 0; byteIndex < length; ++byteIndex) {
                const auto& injections = hashByteInjections(static_cast<uint8_t>(buffer[byteIndex]));
                auto* source = &state;
                auto* destination = &scratch;
                for(size_t round = 0; round < injections.size(); ++round) {
                    packedHashRound<X...>(*source, *destination, transitions, injections[round]);
                    auto* previousSource = source;
                    source = destination;
                    destination = previousSource;
                }
            }
        }

        template<size_t X, size_t R> std::bitset<R> bit_subset(const std::bitset<X>& bits, size_t offset){
            std::bitset<R> result;

            for(size_t i = 0; i < std::min(R, X - offset); i++){
                result[i] = bits[i + offset];
            }

            return result;
        }

        /**
         * Continues a hash from a mid-state with a new block of data
         * */
        template<size_t... X> std::bitset<SC<X...>::value8>* const hashBlock(size_t length, char const* buffer, std::bitset<SC<X...>::value8>* const running) {
            if(buffer && length) {
                PackedHashState<X...> state{};
                constexpr size_t byteCount = SC<X...>::value;
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

        /**
         * Starts a new hash with an initial block of data
         * 
         * The bitset returned must be deleted when no longer needed
         * */
        template<size_t... X> std::bitset<SC<X...>::value8>* const hashBlock(size_t length, char const* buffer) {
            std::bitset<SC<X...>::value8>* initial = new std::bitset<SC<X...>::value8>();
            std::stringstream name;
            name << std::hex;
            using ilst = int[];
            (void) ilst{0, ((void) (name << X << ','), 0)...};
            name << SC<X...>::value;
            return hashBlock<X...>(length, buffer, hashBlock<X...>(name.str().size(), name.str().c_str(), initial));
        }

        /** Selects T bits, wrapping source indexes and repeating bits if T exceeds S. */
        template<size_t S, size_t T> std::bitset<T>* const truncate(std::bitset<S>* const original) {
            static_assert(T > 0, "a truncated hash must contain at least one bit");
            auto ret = new std::bitset<T>();

            size_t offset = original->count();
            for(size_t bit = 0; bit < T; bit++) {
                (*ret)[bit] = (*original)[(bit + ((offset * bit) % S)) % S];
            }

            return ret;
        }

        /** Hashes input with variant X and selects exactly T output bits. */
        template<size_t T, size_t... X> std::bitset<T>* const
        hashBlockTruncated(size_t length, char const* buffer) {
            constexpr size_t fullBits = SC<X...>::value8;
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
         * Converts the bitset holding the hash into a std::string of hex characters
         * */
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
         * Converts the bitset holding the hash into a std::string of base64 characters
         * */
        template<size_t S> std::string finishHash64(std::bitset<S>* const block){
            static constexpr char alphabet[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            constexpr size_t chunkCount = (S + 5) / 6;
            std::string result(chunkCount, 'A');
            size_t source = 0;

            for(size_t chunk = 0; chunk < chunkCount; ++chunk) {
                const size_t width = (chunk == 0 && S % 6 != 0) ? S % 6 : 6;
                uint8_t value = 0;
                for(size_t bit = 0; bit < width; ++bit) {
                    value |= static_cast<uint8_t>((*block)[source + bit]) << bit;
                }
                result[chunk] = alphabet[value];
                source += width;
            }

            return result;
        }

        /**
         * Converts the bitset holding the hash into vector of bytes, unsigned
         * */
        template<size_t S> std::vector<uint8_t>
        packBitsToBytes(std::bitset<S>* const block) {
            static_assert(S % 8 == 0, "packBitsToBytes requires a byte-aligned bitset");
            std::vector<uint8_t> result(S / 8);
            for(size_t byte = 0; byte < result.size(); ++byte) {
                uint8_t value = 0;
                for(size_t bit = 0; bit < 8; ++bit) {
                    value |= static_cast<uint8_t>((*block)[byte * 8 + bit]) << bit;
                }
                result[byte] = value;
            }
            return result;
        }

        /** Packs bitset index zero into the low bit of the first output byte. */
        template<size_t S> std::vector<uint8_t>
        packLowBitsToBytes(std::bitset<S>* const block) {
            std::vector<uint8_t> result((S + 7) / 8, 0);
            for(size_t bit = 0; bit < S; ++bit) {
                result[bit / 8] |= static_cast<uint8_t>((*block)[bit]) << (bit % 8);
            }
            return result;
        }

        /** Packs a full hash after selecting T poker-truncated bits. */
        template<size_t T, size_t... X>
        std::vector<uint8_t> packTruncatedHash(std::bitset<SC<X...>::value8>* const block) {
            constexpr size_t fullBits = SC<X...>::value8;
            static_assert(T > 0, "invalid truncated hash width");
            if constexpr(T == fullBits) {
                return packBitsToBytes(block);
            } else {
                auto truncated = truncate<fullBits, T>(block);
                auto result = packLowBitsToBytes(truncated);
                delete truncated;
                return result;
            }
        }

        template<size_t Bs, size_t... X> std::vector<uint8_t> hmac(size_t keyLength, char const* keyBuffer, size_t msgLength, char const* msgBuffer){
            std::vector<uint8_t> keyBytes;

            if(keyLength > Bs){
                auto block = hashBlock<X...>(keyLength, keyBuffer);
                keyBytes = packBitsToBytes(block);
                delete block;
            } else {
                keyBytes.resize(keyLength);
                std::copy_n(keyBuffer, keyLength, keyBytes.begin());
            }

            keyBytes.resize(Bs);

            std::vector<uint8_t> innerKey(Bs + msgLength), outerKey(Bs);
            for(size_t byte = 0; byte < Bs; ++byte) {
                innerKey[byte] = keyBytes[byte] ^ 0x36;
                outerKey[byte] = keyBytes[byte] ^ 0x5c;
            }
            std::copy_n(msgBuffer, msgLength, innerKey.begin() + Bs);

            auto iblock = hashBlock<X...>(innerKey.size(), (char*) innerKey.data());
            auto ibytes = packBitsToBytes(iblock);
            delete iblock;

            outerKey.resize(Bs + ibytes.size());
            std::copy(ibytes.cbegin(), ibytes.cend(), outerKey.begin() + Bs);

            auto fblock = hashBlock<X...>(outerKey.size(), (char*) outerKey.data());
            auto fbytes = packBitsToBytes(fblock);
            delete fblock;

            return fbytes;
        }

        template<size_t Bs, size_t... X> std::vector<uint8_t> pbkdf2(size_t passLength, char const* passBuffer, size_t saltLength, char const* saltBuffer, int32_t iterations, size_t length){
            std::vector<uint8_t> res;
            int iteration = 1;

            while(res.size() < length){
                std::vector<uint8_t> initial_salt(saltLength);
                std::vector<uint8_t> i_bytes;

                std::copy_n(saltBuffer, saltLength, initial_salt.begin());
                i_bytes.insert(i_bytes.begin(), iteration & 0xFF);
                i_bytes.insert(i_bytes.begin(), (iteration >> 8) & 0xFF);
                i_bytes.insert(i_bytes.begin(), (iteration >> 16) & 0xFF);
                i_bytes.insert(i_bytes.begin(), (iteration >> 24) & 0xFF);

                initial_salt.insert(initial_salt.end(), i_bytes.begin(), i_bytes.end());

                auto current = hmac<Bs, X...>(passLength, passBuffer,
                                              initial_salt.size(), (char*) initial_salt.data());
                std::vector<uint8_t> block(current.size());
                std::copy(current.begin(), current.end(), block.begin());
                size_t uCount = 1;
                while(uCount < static_cast<size_t>(iterations)){
                    current = hmac<Bs, X...>(passLength, passBuffer,
                                             current.size(), (char*) current.data());
                    if(block.size() < current.size()) block.resize(current.size());
                    for(size_t byte = 0; byte < block.size(); byte++){
                        block[byte] ^= current[byte];
                    }
                    ++uCount;
                }

                for(const auto & byte: block){
                    if(res.size() < length) res.push_back(byte);
                }

                iteration++;
            }

            return res;
        }

        /** Cached HMAC pad states for repeated messages under one key. */
        template<size_t Bs, size_t T, size_t... X>
        class PreparedTruncatedHmac {
            static constexpr size_t HashBits = SC<X...>::value8;
            std::bitset<HashBits> innerPadState_;
            std::bitset<HashBits> outerPadState_;

        public:
            static_assert(Bs > 0, "HMAC block size must be positive");
            static_assert(T > 0, "invalid truncated HMAC width");

            PreparedTruncatedHmac(size_t keyLength, char const* keyBuffer)
                : innerPadState_(), outerPadState_() {
                if(keyLength != 0 && keyBuffer == nullptr) {
                    throw std::invalid_argument("hmacTruncated requires a non-null key buffer");
                }

                std::vector<uint8_t> keyBytes(Bs, 0);
                if(keyLength > Bs) {
                    auto keyHash = hashBlockTruncated<T, X...>(keyLength, keyBuffer);
                    const auto packedKey = [&] {
                        if constexpr(T == HashBits) return packBitsToBytes(keyHash);
                        else return packLowBitsToBytes(keyHash);
                    }();
                    std::copy_n(packedKey.begin(), std::min(Bs, packedKey.size()), keyBytes.begin());
                    delete keyHash;
                } else if(keyLength != 0) {
                    std::copy_n(reinterpret_cast<const uint8_t*>(keyBuffer), keyLength, keyBytes.begin());
                }

                std::vector<uint8_t> innerPad(Bs), outerPad(Bs);
                for(size_t byte = 0; byte < Bs; ++byte) {
                    innerPad[byte] = keyBytes[byte] ^ 0x36;
                    outerPad[byte] = keyBytes[byte] ^ 0x5c;
                }

                auto inner = hashBlock<X...>(innerPad.size(), reinterpret_cast<const char*>(innerPad.data()));
                auto outer = hashBlock<X...>(outerPad.size(), reinterpret_cast<const char*>(outerPad.data()));
                innerPadState_ = *inner;
                outerPadState_ = *outer;
                delete inner;
                delete outer;
            }

            std::vector<uint8_t> digest(size_t msgLength, char const* msgBuffer) const {
                if(msgLength != 0 && msgBuffer == nullptr) {
                    throw std::invalid_argument("hmacTruncated requires a non-null message buffer");
                }
                if(msgLength > std::numeric_limits<size_t>::max() - Bs) {
                    throw std::length_error("hmacTruncated input size overflows size_t");
                }

                auto inner = innerPadState_;
                hashBlock<X...>(msgLength, msgBuffer, &inner);
                const auto innerDigest = packTruncatedHash<T, X...>(&inner);

                auto outer = outerPadState_;
                hashBlock<X...>(innerDigest.size(), reinterpret_cast<const char*>(innerDigest.data()), &outer);
                return packTruncatedHash<T, X...>(&outer);
            }
        };

        /** HMAC whose inner and outer digests are both truncated to T bits. */
        template<size_t Bs, size_t T, size_t... X>
        std::vector<uint8_t> hmacTruncated(size_t keyLength, char const* keyBuffer,
                                           size_t msgLength, char const* msgBuffer) {
            if((keyLength != 0 && keyBuffer == nullptr) ||
               (msgLength != 0 && msgBuffer == nullptr)) {
                throw std::invalid_argument("hmacTruncated requires non-null input buffers");
            }
            if(msgLength > std::numeric_limits<size_t>::max() - Bs) {
                throw std::length_error("hmacTruncated input size overflows size_t");
            }
            PreparedTruncatedHmac<Bs, T, X...> prepared(keyLength, keyBuffer);
            return prepared.digest(msgLength, msgBuffer);
        }

        /** PBKDF2-HMAC variant using a T-bit digest and returning exactly length bytes. */
        template<size_t Bs, size_t T, size_t... X>
        std::vector<uint8_t> pbkdf2Truncated(size_t passLength, char const* passBuffer,
                                             size_t saltLength, char const* saltBuffer,
                                             int32_t iterations, size_t length) {
            constexpr size_t hashBytes = (T + 7) / 8;
            static_assert(T > 0, "invalid truncated PBKDF2 width");
            if(iterations <= 0) throw std::invalid_argument("pbkdf2 requires at least one iteration");
            if((passLength != 0 && passBuffer == nullptr) ||
               (saltLength != 0 && saltBuffer == nullptr)) {
                throw std::invalid_argument("pbkdf2Truncated requires non-null input buffers");
            }
            if(length == 0) return {};
            if(saltLength > std::numeric_limits<size_t>::max() - 4) {
                throw std::length_error("pbkdf2 salt size overflows size_t");
            }
            const size_t blockCount = (length - 1) / hashBytes + 1;
            if(blockCount > static_cast<size_t>(UINT32_MAX)) {
                throw std::length_error("pbkdf2 output exceeds its 32-bit block counter");
            }

            PreparedTruncatedHmac<Bs, T, X...> prepared(passLength, passBuffer);
            std::vector<uint8_t> result(length);
            for(size_t blockIndex = 0; blockIndex < blockCount; ++blockIndex) {
                std::vector<uint8_t> salt(saltLength + 4);
                if(saltLength != 0) {
                    std::copy_n(reinterpret_cast<const uint8_t*>(saltBuffer), saltLength, salt.begin());
                }
                const uint32_t counter = static_cast<uint32_t>(blockIndex + 1);
                salt[saltLength] = static_cast<uint8_t>(counter >> 24);
                salt[saltLength + 1] = static_cast<uint8_t>(counter >> 16);
                salt[saltLength + 2] = static_cast<uint8_t>(counter >> 8);
                salt[saltLength + 3] = static_cast<uint8_t>(counter);

                auto current = prepared.digest(salt.size(), reinterpret_cast<const char*>(salt.data()));
                auto block = current;
                for(int32_t iteration = 1; iteration < iterations; ++iteration) {
                    current = prepared.digest(current.size(), reinterpret_cast<const char*>(current.data()));
                    for(size_t byte = 0; byte < block.size(); ++byte) block[byte] ^= current[byte];
                }

                const size_t offset = blockIndex * hashBytes;
                std::copy_n(block.begin(), std::min(hashBytes, length - offset), result.begin() + offset);
            }
            return result;
        }

        /** Writes the reversed-interleaved-bucket permutation into reusable storage. */
        template<typename T>
        void shuffleBlockInto(const std::vector<T>& source, std::vector<T>& result, size_t splits){
            if(splits == 0) throw std::invalid_argument("shuffleBlock requires at least one split");
            if(&source == &result) {
                const auto copy = source;
                shuffleBlockInto(copy, result, splits);
                return;
            }
            result.resize(source.size());
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

        }

        /** Shuffles into reversed interleaved buckets; throws if `splits` is zero. */
        template<typename T> std::vector<T> shuffleBlock(const std::vector<T>& source, size_t splits){
            std::vector<T> result;
            shuffleBlockInto(source, result, splits);
            return result;
        }

        /** Writes the inverse permutation into reusable storage. */
        template<typename T>
        void reverseShuffleBlockInto(const std::vector<T>& source, std::vector<T>& result, size_t splits){
            if(splits == 0) throw std::invalid_argument("reverseShuffleBlock requires at least one split");
            if(&source == &result) {
                const auto copy = source;
                reverseShuffleBlockInto(copy, result, splits);
                return;
            }
            result.resize(source.size());
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

        }

        /** Reverses `shuffleBlock`; throws if `splits` is zero. */
        template<typename T> std::vector<T> reverseShuffleBlock(const std::vector<T>& source, size_t splits){
            std::vector<T> result;
            reverseShuffleBlockInto(source, result, splits);
            return result;
        }

        /**
         * Per-file key schedule. PBKDF2 runs once at construction; each block's
         * round material is then expanded with a context containing the encrypted
         * first block, previous ciphertext block, block index, and operation purpose.
         */
        template<size_t BSize, size_t T, size_t... X> class TruncatedShuffleKdfContext {
            static constexpr size_t HashBytes = (T + 7) / 8;
            static constexpr size_t HashBits = T;
            static constexpr size_t KdfBlockSize = BSize > HashBytes ? BSize : HashBytes;

            std::bitset<HashBits> key_;
            std::vector<uint8_t> kdfKey_;
            std::vector<uint8_t> kdfSalt_;
            std::vector<uint8_t> fileContext_;
            std::bitset<SC<X...>::value8> innerPadState_;
            std::bitset<SC<X...>::value8> outerPadState_;
            std::vector<std::array<uint8_t, 1U << CHAR_BIT>> substitutionSchedule_;
            std::vector<std::array<uint8_t, 1U << CHAR_BIT>> inverseSubstitutionSchedule_;
            std::vector<size_t> roundSplits_;

            static void appendInteger(std::vector<uint8_t>& destination, std::uint64_t value) {
                for(size_t byte = 0; byte < 8; ++byte) {
                    destination.push_back(static_cast<uint8_t>(value >> (56 - byte * 8)));
                }
            }

            static void appendBytes(std::vector<uint8_t>& destination, const uint8_t* bytes, size_t length) {
                appendInteger(destination, length);
                if(length != 0) destination.insert(destination.end(), bytes, bytes + length);
            }

            static std::vector<uint8_t> domain(const std::string& label) {
                static constexpr char prefix[] = "SLR-SHUFFLE-KEYSCHEDULE";
                std::vector<uint8_t> result(prefix, prefix + sizeof(prefix) - 1);
                result.push_back(1); // key-schedule version
                appendInteger(result, BSize);
                appendInteger(result, sizeof...(X));
                using variant_list = int[];
                (void) variant_list{0, ((void) appendInteger(result, X), 0)...};
                if constexpr(T != SC<X...>::value8) appendInteger(result, T);
                appendBytes(result, reinterpret_cast<const uint8_t*>(label.data()), label.size());
                return result;
            }

            void initializeExpanderHmac() {
                std::vector<uint8_t> innerPad(KdfBlockSize);
                std::vector<uint8_t> outerPad(KdfBlockSize);
                std::vector<uint8_t> normalizedKey(KdfBlockSize, 0);
                std::copy_n(kdfKey_.cbegin(), std::min(kdfKey_.size(), normalizedKey.size()),
                            normalizedKey.begin());
                for(size_t byte = 0; byte < KdfBlockSize; ++byte) {
                    innerPad[byte] = normalizedKey[byte] ^ 0x36;
                    outerPad[byte] = normalizedKey[byte] ^ 0x5c;
                }

                auto inner = hashBlock<X...>(innerPad.size(), reinterpret_cast<const char*>(innerPad.data()));
                auto outer = hashBlock<X...>(outerPad.size(), reinterpret_cast<const char*>(outerPad.data()));
                innerPadState_ = *inner;
                outerPadState_ = *outer;
                delete inner;
                delete outer;
            }

            std::vector<uint8_t> expandHmac(const std::vector<uint8_t>& message) const {
                auto inner = innerPadState_;
                hashBlock<X...>(message.size(), reinterpret_cast<const char*>(message.data()), &inner);
                auto innerBytes = packTruncatedHash<T, X...>(&inner);

                auto outer = outerPadState_;
                hashBlock<X...>(innerBytes.size(), reinterpret_cast<const char*>(innerBytes.data()), &outer);
                return packTruncatedHash<T, X...>(&outer);
            }

            void initializeSubstitutionSchedule() {
                std::vector<uint8_t> substitution(1U << CHAR_BIT);
                for(size_t value = 0; value < substitution.size(); ++value) {
                    substitution[value] = static_cast<uint8_t>(value);
                }
                substitutionSchedule_.reserve(HashBits);
                inverseSubstitutionSchedule_.reserve(HashBits);
                roundSplits_.reserve(HashBits);

                size_t roundSplit = 0;
                std::vector<uint8_t> substitutionScratch(substitution.size());
                for(size_t pass = 0; pass < key_.size(); ++pass) {
                    if(key_[pass]) ++roundSplit;
                    shuffleBlockInto(substitution, substitutionScratch, (roundSplit % 14) + 2);
                    substitution.swap(substitutionScratch);
                    std::array<uint8_t, 1U << CHAR_BIT> step{};
                    std::copy(substitution.begin(), substitution.end(), step.begin());
                    substitutionSchedule_.push_back(step);
                    std::array<uint8_t, 1U << CHAR_BIT> inverse{};
                    for(size_t input = 0; input < substitution.size(); ++input) {
                        inverse[substitution[input]] = static_cast<uint8_t>(input);
                    }
                    inverseSubstitutionSchedule_.push_back(inverse);
                    roundSplits_.push_back(roundSplit);
                }
            }

            std::vector<uint8_t> expandRoundBytes(size_t saltLength, char const* saltBuffer,
                                                  std::uint64_t blockIndex, const std::string& purpose) const {
                if(saltLength != 0 && saltBuffer == nullptr) {
                    throw std::invalid_argument("ShuffleKdfContext requires a non-null block context");
                }
                if(blockIndex != 0 && fileContext_.empty()) {
                    throw std::logic_error("set the encrypted IV as the file context before later blocks");
                }
                if(BSize > std::numeric_limits<size_t>::max() / HashBits) {
                    throw std::length_error("shuffle round material size overflows size_t");
                }

                auto info = domain("context-bound-expand");
                appendInteger(info, blockIndex);
                appendBytes(info, fileContext_.data(), fileContext_.size());
                appendBytes(info, reinterpret_cast<const uint8_t*>(saltBuffer), saltLength);
                appendBytes(info, reinterpret_cast<const uint8_t*>(purpose.data()), purpose.size());

                const size_t required = BSize * HashBits;
                std::vector<uint8_t> result;
                result.reserve(required);
                const size_t counterOffset = info.size();
                info.resize(counterOffset + 8);
                std::uint64_t counter = 1;
                while(result.size() < required) {
                    const std::uint64_t currentCounter = counter++;
                    for(size_t byte = 0; byte < 8; ++byte) {
                        info[counterOffset + byte] =
                            static_cast<uint8_t>(currentCounter >> (56 - byte * 8));
                    }
                    auto digest = expandHmac(info);
                    if(digest.empty()) throw std::runtime_error("shuffle expander produced an empty digest");
                    const size_t count = std::min(digest.size(), required - result.size());
                    result.insert(result.end(), digest.begin(), digest.begin() + count);
                }
                return result;
            }

            std::vector<uint8_t> encryptWithPurpose(size_t saltLength, char const* saltBuffer,
                                                    size_t length, char const* buffer,
                                                    std::uint64_t blockIndex, const std::string& purpose) const {
                const size_t splitModulus = static_cast<size_t>(std::sqrt(BSize * 8.0)) - 2;
                std::bitset<BSize * 8> blockBits;
                std::vector<uint8_t> blockBytes(BSize, 0);
                std::vector<bool> shuffle(BSize * 8), shuffleScratch(BSize * 8);
                if(buffer) std::copy_n(buffer, std::min(length, BSize), blockBytes.begin());
                const auto roundBytes = expandRoundBytes(saltLength, saltBuffer, blockIndex, purpose);

                for(size_t pass = 0; pass < key_.size(); ++pass) {
                    const size_t roundSplit = roundSplits_[pass];
                    const auto& shuffleSub = substitutionSchedule_[pass];

                    for(size_t bytePos = 0; bytePos < BSize; ++bytePos) {
                        const uint8_t roundByte = roundBytes[pass * BSize + bytePos];
                        const uint8_t substituted = shuffleSub[roundByte ^ blockBytes[bytePos]];
                        for(size_t bit = 0; bit < 8; ++bit) {
                            shuffle[bytePos * 8 + bit] = (substituted >> bit) & 1U;
                        }
                    }

                    shuffleBlockInto(shuffle, shuffleScratch, (roundSplit % splitModulus) + 2);
                    shuffle.swap(shuffleScratch);
                    for(size_t bit = 0; bit < shuffle.size(); ++bit) blockBits[bit] = shuffle[bit];
                    blockBytes = packBitsToBytes(&blockBits);
                }
                return blockBytes;
            }

        public:
            static_assert(BSize >= 2, "shuffle requires a block size of at least two bytes");
            static_assert(HashBits > 0, "shuffle requires a non-empty hash variant");

            TruncatedShuffleKdfContext(size_t passLength, char const* passBuffer,
                                       size_t saltLength, char const* saltBuffer, size_t iterations)
                : key_(), kdfKey_(), kdfSalt_(), fileContext_(), innerPadState_(), outerPadState_(),
                  substitutionSchedule_(), inverseSubstitutionSchedule_(), roundSplits_() {
                if(iterations == 0 || iterations > static_cast<size_t>(std::numeric_limits<std::int32_t>::max())) {
                    throw std::invalid_argument("shuffle KDF iterations must fit a positive int32_t");
                }
                if((passLength != 0 && passBuffer == nullptr) || (saltLength != 0 && saltBuffer == nullptr)) {
                    throw std::invalid_argument("shuffle KDF requires non-null password and salt buffers");
                }

                auto hash = hashBlockTruncated<T, X...>(passLength, passBuffer);
                key_ = *hash;
                delete hash;

                if(saltLength != 0) {
                    const auto* saltBytes = reinterpret_cast<const uint8_t*>(saltBuffer);
                    kdfSalt_.assign(saltBytes, saltBytes + saltLength);
                }

                auto kdfSalt = domain("pbkdf2-root");
                appendBytes(kdfSalt, kdfSalt_.data(), kdfSalt_.size());
                kdfKey_ = pbkdf2Truncated<KdfBlockSize, T, X...>(
                    passLength, passBuffer, kdfSalt.size(), reinterpret_cast<const char*>(kdfSalt.data()),
                    static_cast<std::int32_t>(iterations), HashBytes);
                initializeExpanderHmac();
                initializeSubstitutionSchedule();
            }

            /** Set the encrypted first block as nonce/context for all later blocks. */
            void setFileContext(size_t length, char const* buffer) {
                if(length == 0 || buffer == nullptr) {
                    throw std::invalid_argument("ShuffleKdfContext requires a non-empty file context");
                }
                if(!fileContext_.empty()) {
                    throw std::logic_error("ShuffleKdfContext file context is already set");
                }
                const auto* bytes = reinterpret_cast<const uint8_t*>(buffer);
                fileContext_.assign(bytes, bytes + length);
            }

            std::vector<uint8_t> encryptBlock(size_t saltLength, char const* saltBuffer,
                                              size_t length, char const* buffer,
                                              std::uint64_t blockIndex) const {
                return encryptWithPurpose(saltLength, saltBuffer, length, buffer, blockIndex, "ciphertext-block");
            }

            std::vector<uint8_t> decryptBlock(size_t saltLength, char const* saltBuffer,
                                              size_t length, char const* buffer,
                                              std::uint64_t blockIndex) const {
                const size_t splitModulus = static_cast<size_t>(std::sqrt(BSize * 8.0)) - 2;
                std::bitset<BSize * 8> blockBits;
                std::vector<uint8_t> blockBytes(BSize, 0);
                std::vector<bool> shuffle(BSize * 8), shuffleScratch(BSize * 8);
                if(buffer) std::copy_n(buffer, std::min(length, BSize), blockBytes.begin());
                const auto roundBytes = expandRoundBytes(saltLength, saltBuffer, blockIndex, "ciphertext-block");

                for(size_t pass = 0; pass < key_.size(); ++pass) {
                    const size_t reversePass = key_.size() - 1 - pass;
                    const size_t roundSplit = roundSplits_[reversePass];
                    for(size_t bytePos = 0; bytePos < BSize; ++bytePos) {
                        const std::bitset<8> bits(blockBytes[bytePos]);
                        for(size_t bit = 0; bit < 8; ++bit) shuffle[bytePos * 8 + bit] = bits[bit];
                    }

                    reverseShuffleBlockInto(shuffle, shuffleScratch, (roundSplit % splitModulus) + 2);
                    shuffle.swap(shuffleScratch);
                    for(size_t bit = 0; bit < shuffle.size(); ++bit) blockBits[bit] = shuffle[bit];
                    blockBytes = packBitsToBytes(&blockBits);

                    for(size_t bytePos = 0; bytePos < BSize; ++bytePos) {
                        const uint8_t roundByte = roundBytes[reversePass * BSize + bytePos];
                        blockBytes[bytePos] = static_cast<uint8_t>(
                            inverseSubstitutionSchedule_[reversePass][blockBytes[bytePos]] ^ roundByte);
                    }
                }
                return blockBytes;
            }

            std::vector<uint8_t> paddingMask(size_t saltLength, char const* saltBuffer,
                                             std::uint64_t blockIndex) const {
                return encryptWithPurpose(saltLength, saltBuffer, saltLength, saltBuffer,
                                         blockIndex, "padding-mask");
            }
        };

        template<size_t BSize, size_t... X>
        using ShuffleKdfContext = TruncatedShuffleKdfContext<BSize, SC<X...>::value8, X...>;

        template<size_t BSize, size_t... X> std::vector<uint8_t>
        shuffleEncrypt(size_t passLength, char const* passBuffer, size_t saltLength, char const* saltBuffer,
                       size_t length, char const* buffer, size_t iterations) {
            ShuffleKdfContext<BSize, X...> context(passLength, passBuffer, saltLength, saltBuffer, iterations);
            return context.encryptBlock(saltLength, saltBuffer, length, buffer, 0);
        }

        template<size_t BSize, size_t... X> std::vector<uint8_t>
        shuffleDecrypt(size_t passLength, char const* passBuffer, size_t saltLength, char const* saltBuffer,
                       size_t length, char const* buffer, size_t iterations) {
            ShuffleKdfContext<BSize, X...> context(passLength, passBuffer, saltLength, saltBuffer, iterations);
            return context.decryptBlock(saltLength, saltBuffer, length, buffer, 0);
        }

        template<size_t BSize, size_t T, size_t... X> std::vector<uint8_t>
        shuffleEncryptTruncated(size_t passLength, char const* passBuffer,
                                size_t saltLength, char const* saltBuffer,
                                size_t length, char const* buffer, size_t iterations) {
            TruncatedShuffleKdfContext<BSize, T, X...> context(
                passLength, passBuffer, saltLength, saltBuffer, iterations);
            return context.encryptBlock(saltLength, saltBuffer, length, buffer, 0);
        }

        template<size_t BSize, size_t T, size_t... X> std::vector<uint8_t>
        shuffleDecryptTruncated(size_t passLength, char const* passBuffer,
                                size_t saltLength, char const* saltBuffer,
                                size_t length, char const* buffer, size_t iterations) {
            TruncatedShuffleKdfContext<BSize, T, X...> context(
                passLength, passBuffer, saltLength, saltBuffer, iterations);
            return context.decryptBlock(saltLength, saltBuffer, length, buffer, 0);
        }
    }
}
#endif /*GUARD_SLR_CRYPTO*/

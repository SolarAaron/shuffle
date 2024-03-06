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

namespace slr{
	namespace crypto{
		namespace /* unnamed */{
			template<typename T> constexpr T htonT (T value) noexcept {
			#if __BYTE_ORDER == __LITTLE_ENDIAN
			  char* ptr = reinterpret_cast<char*>(&value);
			  std::reverse (ptr, ptr + sizeof(T));
			#endif
			  return value;
			}
			
			template<size_t S, size_t... X> struct SC{
				enum{
					value = S*S * SC<X...>::value,
					value8 = 8*S*S * SC<X...>::value
				};
			};
			
			template<size_t S> struct SC<S>{
				enum{
					value = S*S,
					value8 = 8*S*S
				};
			};
		}
		
		template<size_t S, size_t Bs, size_t Ks, size_t Kd = 1, size_t... X> class bitFiddler{
			public:
			/**
			 * Re-splits the bitsets at src and passes them to the next iteration as specified in ...X
			 * it should hold that B*K*K = S*8
			 * The first pass may be B = S*8, K = 1, but the bitset in src must not be the same instance as sink
			 * */
			static void bitwisePass(std::bitset<S*8>* const sink, std::array<std::bitset<Bs>, Ks*Ks>* const src){
				std::array<std::bitset<(S*8)/(Kd*Kd)>, Kd*Kd> step;

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
				bitFiddler<S, (S*8)/(Kd*Kd), Kd, X...>::bitwisePass(sink, &step);
			}
		};
		
		template<size_t S, size_t Bs, size_t Ks, size_t Kd> class bitFiddler<S, Bs, Ks, Kd>{
			public:
			/**
			 * Joins the bitsets at src into sink, as a final step after the D split
			 * it should hold that B*K*K = S*8
			 * */
			static void bitwisePass(std::bitset<S*8>* const sink, std::array<std::bitset<Bs>, Ks*Ks>* const src) {
				std::array<std::bitset<(S*8)/(Kd*Kd)>, Kd*Kd> step;

				size_t dest = 0;

				for(auto it = src->cbegin(); it < src->cend(); ++it){
                    for(size_t bit = 0; bit < it->size(); bit++){
                        step.at(dest % step.size()) <<= 1;
                        step.at(dest % step.size())[0] = (*it)[(it->size() - 1) - bit];
                        dest++;
                    }
				}

				for(; dest < S*8; dest++){
					step.at(dest / ((S*8)/(Kd*Kd))) <<= 1;
					step.at(dest / ((S*8)/(Kd*Kd)))[0] = src->at(dest / Bs)[dest % Bs];
				}

                for(auto it = step.cbegin() ; it != step.cend(); ++it){
                    for(size_t bit = 0; bit < it->size(); bit++){
                        (*sink) <<= 1;
                        (*sink)[0] = (*it)[(it->size() - 1) - bit];
                    }
                }
			}
		};

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
		template<size_t... X> std::bitset<SC<X...>::value8>* const hashBlock(size_t length, char const* buffer, std::bitset<SC<X...>::value8>* const running){
			if(buffer) for(size_t i = 0; i < length; i++){
				uint8_t byte = buffer[i];
                std::bitset<8> explodedByte = std::bitset<8>(byte);
				for(size_t bit = 0; bit < explodedByte.size(); bit++){
                    std::bitset<SC<X...>::value8> bitwise_f = *running;
                    std::bitset<SC<X...>::value8> bitwise_b = *running;
                    std::array<std::bitset<SC<X...>::value8>, 1> src;
					
					// shuffle current hash
					src[0] = std::bitset<SC<X...>::value8>(running->to_string());
                    bitFiddler<SC<X...>::value, SC<X...>::value8, 1, X...>::bitwisePass(&bitwise_f, &src);
                    bitFiddler<SC<X...>::value, SC<X...>::value8, 1, X...>::bitwisePass(&bitwise_b, &src);

					// hash pass 1 -- shift current bit forward into first position and shuffle
					bitwise_f <<= 1;
					bitwise_f[0] = explodedByte[bit];

					src[0] = std::bitset<SC<X...>::value8>(bitwise_f.to_string());
					bitFiddler<SC<X...>::value, SC<X...>::value8, 1, X...>::bitwisePass(&bitwise_f, &src);

					// hash pass 2 -- shift current bit backward into last position and shuffle
					bitwise_b >>= 1;
					bitwise_b[ (SC<X...>::value8) - 1] = explodedByte[ (explodedByte.size() - 1) - bit ];

					src[0] = std::bitset<SC<X...>::value8>(bitwise_b.to_string());
					bitFiddler<SC<X...>::value, SC<X...>::value8, 1, X...>::bitwisePass(&bitwise_b, &src);

					// finally -- add into running hash
					uint16_t bitsum = 0;

                    for(size_t x = 0; x < (SC<X...>::value8); x+=8){
						uint16_t a = bit_subset<SC<X...>::value8, 8>(*running, x).to_ulong(),
                        b = bit_subset<SC<X...>::value8, 8>(bitwise_f, x).to_ulong(),
                        c = bit_subset<SC<X...>::value8, 8>(bitwise_b, x).to_ulong();
                        bitsum += a;
                        bitsum += b;
                        bitsum += c;
						auto cur = std::bitset<8>(bitsum);
                        for(size_t bx = 0; bx < 8; bx++)
						    (*running)[x + bx] = cur[bx];
						bitsum >>= 8;
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
		template<size_t... X> std::bitset<SC<X...>::value8>* const hashBlock(size_t length, char const* buffer){
			std::bitset<SC<X...>::value8>* initial = new std::bitset<SC<X...>::value8>();
			std::stringstream name;
			name << std::hex;
			using ilst = int[];
			(void) ilst {0, ( (void)(name << X << ','), 0 )...};
			name << SC<X...>::value;
			return hashBlock<X...>(length, buffer, hashBlock<X...>(name.str().size(),name.str().c_str(),initial));
		}
		
		/**
		 * Converts the bitset holding the hash into a std::string of hex characters
		 * */
		template<size_t S> std::string finishHash(std::bitset<S>* const block){
            std::vector<char> ret_v;
			
			for(size_t pos = S; pos > 0; pos -= 8){
				std::stringstream buf;
				std::bitset<8> bits;
				for(size_t bit = 8; bit > 0; bit--){
					bits[8 - bit] = (*block)[pos - bit];
				}
				buf << std::hex << std::setfill('0') << std::setw(2);
				buf << bits.to_ulong();
                auto str = buf.str();
                ret_v.insert(ret_v.begin(), str.begin(), str.end());
			}

            return std::string(ret_v.begin(), ret_v.end());
		}

        /**
         * Converts the bitset holding the hash into a std::string of base64 characters
         * */
        template<size_t S> std::string finishHash64(std::bitset<S>* const block){
            std::vector<char> ret_v;
            bool stop = false;

            for(size_t pos = S; (pos > 0) && (!stop); pos -= 6){
                std::bitset<6> bits;
                for(size_t bit = 6; bit > 0; bit--){
                    if(pos == bit) stop = true;
                    if(pos >= bit) bits[6 - bit] = (*block)[pos - bit];
                }
                char b64char;

                if(bits.to_ulong() < 26) b64char = ('A' + bits.to_ulong());
                else if(bits.to_ulong() < 52) b64char = ('a' + (bits.to_ulong() - 26));
                else if(bits.to_ulong() < 62) b64char = ('0' + (bits.to_ulong() - 52));
                else if(bits.to_ulong() == 62) b64char = '+';
                else if(bits.to_ulong() == 63) b64char = '/';
                else b64char = '=';

                ret_v.insert(ret_v.begin(), b64char);
            }

            return std::string(ret_v.begin(), ret_v.end());
        }

		/**
		 * Converts the bitset holding the hash into vector of bytes, unsigned
		 * */
		template<size_t S> std::vector<uint8_t> packBitsToBytes(std::bitset<S>* const block){
			std::vector<uint8_t> ret;

			for(size_t pos = S; pos > 0; pos -= 8){
				std::bitset<8> bits;
				for(size_t bit = 8; bit > 0; bit--){
					bits[8 - bit] = (*block)[pos - bit];
				}
				ret.insert(ret.begin(), bits.to_ulong());
			}

			return ret;
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
            std::transform(keyBytes.cbegin(), keyBytes.cend(), innerKey.begin(), [](uint8_t byte) -> uint8_t {return byte ^ 0x36;});
            std::transform(keyBytes.cbegin(), keyBytes.cend(), outerKey.begin(), [](uint8_t byte) -> uint8_t {return byte ^ 0x5c;});
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
                std::vector<std::vector<uint8_t>> hash_iter;

                std::vector<uint8_t> initial_salt(saltLength);
                std::vector<uint8_t> i_bytes;

                std::copy_n(saltBuffer, saltLength, initial_salt.begin());
                i_bytes.insert(i_bytes.begin(), iteration & 0xFF);
                i_bytes.insert(i_bytes.begin(), (iteration >> 8) & 0xFF);
                i_bytes.insert(i_bytes.begin(), (iteration >> 16) & 0xFF);
                i_bytes.insert(i_bytes.begin(), (iteration >> 24) & 0xFF);

                initial_salt.insert(initial_salt.end(), i_bytes.begin(), i_bytes.end());

                hash_iter.push_back(hmac<Bs, X...>(passLength, passBuffer, initial_salt.size(), (char*) initial_salt.data()));
                while(hash_iter.size() < iterations){
                    hash_iter.push_back(hmac<Bs, X...>(passLength, passBuffer, hash_iter.back().size(), (char*) hash_iter.back().data()));
                }

                std::vector<uint8_t> block;

                for(const auto & it : hash_iter){
                    if(block.size() < it.size()) block.resize(it.size());
                    for(size_t byte = 0; byte < block.size(); byte++){
                        block[byte] ^= it[byte];
                    }
                }

                for(const auto & byte: block){
                    if(res.size() < length) res.push_back(byte);
                }

                iteration++;
            }

            return res;
        }

        template<typename T> std::vector<T> shuffleBlock(const std::vector<T>& source, size_t splits){
            std::vector<std::vector<T>> shuffle;

            for(size_t i = 0; i < source.size(); i++){
                size_t pos = (i % splits);

                while(shuffle.size() <= pos){
                    shuffle.emplace_back();
                }

                shuffle[pos].insert(shuffle[pos].begin(), source[i]);
            }

            std::vector<T> result;

            for(auto it = shuffle.cbegin(); it != shuffle.cend(); ++it){
                for(T elem : *it){
                    result.push_back(elem);
                }
            }

            return result;
        }

        template<typename T> std::vector<T> reverseShuffleBlock(const std::vector<T>& source, size_t splits){
            std::vector<T> result;

            std::vector<size_t> indices, shuffled;
            for(size_t idx = 0; idx < source.size(); idx++) indices.push_back(idx);

            shuffled = shuffleBlock(indices, splits);

            std::vector<std::pair<size_t, T>> deshuffle;

            for(size_t x = 0; x < shuffled.size(); x++){
                deshuffle.push_back(std::make_pair(shuffled[x], source[x]));
            }

            std::sort(deshuffle.begin(), deshuffle.end(), [] (const std::pair<size_t, T>& a, const std::pair<size_t, T>& b)-> bool {return std::less<size_t>{}(std::get<0>(a), std::get<0>(b));});

            for(auto p: deshuffle) result.push_back(std::get<1>(p));

            return result;
        }

        template<size_t BSize, size_t... X> std::vector<uint8_t> shuffleEncrypt(size_t passLength, char const* passBuffer, size_t saltLength, char const* saltBuffer, size_t length, char const* buffer){
            std::bitset<BSize * 8> blockBits;
            std::vector<uint8_t> blockBytes;
            std::vector<uint8_t> shuffleSub;
            auto key = hashBlock<X...>(passLength, passBuffer);
            auto roundBytes = pbkdf2<BSize, X...>(passLength, passBuffer, saltLength, saltBuffer, SC<X...>::value8, BSize * key->size());

            for(size_t sub = 0; sub < (1 << (sizeof(uint8_t) * CHAR_BIT)); sub++)
                shuffleSub.push_back(sub);
            if(buffer) for(size_t i = 0; i < std::min(length, BSize); i++){
                    blockBytes.push_back(buffer[i]);
            }
            blockBytes.resize(BSize);

            size_t roundSplit = 0;

            for(size_t pass = 0; pass < key->size(); pass++){
                std::vector<bool> shuffle;

                if ((*key)[pass]) roundSplit++;

                shuffleSub = shuffleBlock(shuffleSub, (roundSplit % 30) + 2);

                for(size_t bytePos = 0; bytePos < BSize; bytePos++){
                    uint8_t roundByte = roundBytes[(pass * BSize) + bytePos];
                    uint8_t blockByte = blockBytes[bytePos];
                    auto roundBits = std::bitset<8>(shuffleSub[roundByte ^ blockByte]);

                    for(uint8_t bit  = 0; bit < 8; bit++){
                        shuffle.push_back(roundBits[bit]);
                    }
                }

                shuffle = shuffleBlock(shuffle, (roundSplit % (BSize - 2)) + 2);

                size_t offset = 0;

                for(bool bit : shuffle){
                    blockBits[offset] = bit;
                    offset++;
                }

                blockBytes = packBitsToBytes(&blockBits);
            }

            delete key;

            return blockBytes;
        }

        template<size_t BSize, size_t... X> std::vector<uint8_t> shuffleDecrypt(size_t passLength, char const* passBuffer, size_t saltLength, char const* saltBuffer, size_t length, char const* buffer){
            std::bitset<BSize * 8> blockBits;
            std::vector<uint8_t> blockBytes;
            std::vector<uint8_t> shuffleSub;
            auto key = hashBlock<X...>(passLength, passBuffer);
            auto roundBytes = pbkdf2<BSize, X...>(passLength, passBuffer, saltLength, saltBuffer, SC<X...>::value8, BSize * key->size());

            for(size_t sub = 0; sub < (1 << (sizeof(uint8_t) * CHAR_BIT)); sub++)
                shuffleSub.push_back(sub);
            if(buffer) for(size_t i = 0; i < std::min(length, BSize); i++){
                    blockBytes.push_back(buffer[i]);
                }
            blockBytes.resize(BSize);

            size_t roundSplit = 0;

            for(size_t pass = 0; pass < key->size(); pass++){ // regenerate substitution schedule
                if ((*key)[pass]) roundSplit++;
                shuffleSub = shuffleBlock(shuffleSub, (roundSplit % 30) + 2);
            }

            for(size_t pass = 0; pass < key->size(); pass++){
                size_t rpass = (key->size() - 1) - pass;
                std::vector<bool> shuffle;

                for(size_t bytePos = 0; bytePos < BSize; bytePos++){
                    uint8_t blockByte = blockBytes[bytePos];
                    auto roundBits = std::bitset<8>(blockByte);

                    for(uint8_t bit  = 0; bit < 8; bit++){
                        shuffle.push_back(roundBits[bit]);
                    }
                }

                shuffle = reverseShuffleBlock(shuffle, (roundSplit % (BSize - 2)) + 2);

                size_t offset = 0;

                for(bool bit : shuffle){
                    blockBits[offset] = bit;
                    offset++;
                }

                blockBytes = packBitsToBytes(&blockBits);

                for(size_t bytePos = 0; bytePos < BSize; bytePos++){
                    uint8_t roundByte = roundBytes[(rpass * BSize) + bytePos];
                    uint8_t blockByte = blockBytes[bytePos];

                    auto find_it = std::find(shuffleSub.begin(), shuffleSub.end(), blockByte);
                    blockBytes[bytePos] = (std::distance(shuffleSub.begin(), find_it)) ^ roundByte;
                }

                shuffleSub = reverseShuffleBlock(shuffleSub, (roundSplit % 30) + 2);
                if ((*key)[rpass]) roundSplit--;
            }

            delete key;

            return blockBytes;
        }
	}
}
#endif /*GUARD_SLR_CRYPTO*/

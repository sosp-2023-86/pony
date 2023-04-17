#pragma once

#include <array>
#include <type_traits>

#include <dory/crypto/hash/blake3.hpp>
#include <dory/shared/branching.hpp>

#include "config.hpp"
#include "types.hpp"

namespace dory::pony {

/**
 * @brief A hash large enough know which secrets to reveal.
 *
 */
class WotsHash {
 public:
  WotsHash(Hash const& pk_hash, Hash const& nonce, uint8_t const* const begin,
           uint8_t const* const end) {
    // Computing the hash
    auto hasher = crypto::hash::blake3_init();
    std::array<Hash, 2> prefix = {pk_hash, nonce};  // A Blake block is 64B
    crypto::hash::blake3_update(hasher, prefix);
    crypto::hash::blake3_update(hasher, begin, end);
    crypto::hash::blake3_final_there(hasher, hash.data(), hash.size());
    // Computing the checksum (which is at most 8 bytes)
    uint64_t& csum = *reinterpret_cast<uint64_t*>(checksum.data());
    for (size_t secret = 0; secret < wots::L1; secret++) {
      csum += SecretsDepth - 1 - getSecretDepth(secret);
    }
  }

  inline size_t getSecretDepth(size_t const secret_index) const {
    static size_t constexpr SecretsDepthMask = SecretsDepth - 1;

    // We find out whether to use the hash or the checksum.
    uint8_t const* const bytes =
        secret_index < wots::L1 ? hash.data() : checksum.data();
    size_t const word_index =
        secret_index < wots::L1 ? secret_index : (secret_index - wots::L1);

    auto const bit_offset = word_index * wots::LogSecretsDepth;
    auto const div = std::ldiv(bit_offset, 8);
    auto const byte_offset = div.quot;
    auto const remaining_bit_offset = div.rem;
    // Due to Intel's little endianness, the initialized bytes hold the LSBs.
    // Given that C++'s shift operator work on the value and not on the memory
    // representation, we need to read the LSB
    return (*reinterpret_cast<size_t const*>(&bytes[byte_offset]) >>
            remaining_bit_offset) &
           SecretsDepthMask;
  }

 private:
  static size_t constexpr HashBits = wots::L1 * wots::LogSecretsDepth;
  static size_t constexpr HashBytes = (HashBits - 1) / 8 + 1;  // = 128

 public:
  std::array<uint8_t, HashBytes> hash;
  std::array<uint8_t, 8> checksum = {};  // 8 is more than necessary
};

}  // namespace dory::pony

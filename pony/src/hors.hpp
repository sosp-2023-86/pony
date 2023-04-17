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
class HorsHash {
 public:
  HorsHash(Hash const& pk_hash, Hash const& nonce, uint8_t const* const begin,
           uint8_t const* const end) {
    auto hasher = crypto::hash::blake3_init();
    std::array<Hash, 2> prefix = {pk_hash, nonce};  // A Blake block is 64B
    crypto::hash::blake3_update(hasher, prefix);
    crypto::hash::blake3_update(hasher, begin, end);
    crypto::hash::blake3_final_there(hasher, bytes.data(), bytes.size());
  }

  inline size_t getSecretIndex(size_t const bit_offset) const {
    static size_t constexpr SecretIndexMask = SecretsPerSecretKey - 1;
    static bool constexpr ByteAlignedSecrets =
        hors::LogSecretsPerSecretKey % 8 == 0;

    // We assume we don't overflow.
    auto const [byte_offset,
                remaining_bit_offset] = [&]() -> std::pair<size_t, size_t> {
      if constexpr (ByteAlignedSecrets) {
        // If secrets cover full bytes, we let the compiler know that the
        // remaining bit offset will always be 0 so that it can optimize.
        return {bit_offset / 8ul, 0ul};
      } else {
        auto const div = std::ldiv(bit_offset, 8);
        return {div.quot, div.rem};
      }
    }();

    // Due to Intel's little endianness, the initialized bytes hold the LSBs.
    // Given that C++'s shift operator work on the value and not on the memory
    // representation, we need to read the LSBs.
    return (*reinterpret_cast<size_t const*>(&bytes[byte_offset]) >>
            remaining_bit_offset) &
           SecretIndexMask;
  }

 private:
  static size_t constexpr Bits =
      hors::LogSecretsPerSecretKey * SecretsPerSignature;
  static size_t constexpr Bytes = (Bits - 1) / 8 + 1;

 public:
  std::array<uint8_t, Bytes> bytes;
};

}  // namespace dory::pony

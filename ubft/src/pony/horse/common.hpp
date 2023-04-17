#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <random>
#include <vector>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <fmt/ranges.h>

#include <dory/crypto/hash/blake3.hpp>

namespace dory::ubft::pony::horse {

using RandomBytesEngine =
    std::independent_bits_engine<std::default_random_engine, 8, uint8_t>;

// Note: The last bits of the hash won't be used if not a multiple.
size_t constexpr bits_per_secret = 8;
size_t constexpr t = 1 << bits_per_secret;
size_t constexpr secret_index_mask = t - 1;

using Hash = crypto::hash::Blake3Hash;
bool constexpr ByteAlignedSecrets = (sizeof(Hash) * 8) % bits_per_secret == 0;
// static_assert(ByteAlignedSecrets);
using Secret = Hash;

size_t constexpr d = 1024;
static_assert(d >= 1);
using Chains = std::array<std::array<Hash, d + 1>, t>;
using State = std::array<size_t, t>;

size_t constexpr secrets_per_signature =
    sizeof(Hash) * 8 / bits_per_secret;  // Rounded up
using Signature = std::array<Secret, secrets_per_signature>;

template <size_t MessageSize>
struct SignedMessage {
  // size_t seq;
  std::array<uint8_t, MessageSize> message;
  Signature signature;
};
// static_assert(offsetof(SignedMessage<128>, message) == sizeof(size_t));

inline size_t get_secret_index(Hash const& hash, size_t const bit_offset);
inline size_t get_secret_index(Hash const& hash, size_t const bit_offset) {
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

  return (*reinterpret_cast<size_t const*>(&hash[byte_offset])
          << remaining_bit_offset) &
         secret_index_mask;
}

class PrivateKey {
 public:
  PrivateKey(RandomBytesEngine& rbe) {
    // We generate the chains.
    for (auto& chain : chains) {
      auto* const begin = reinterpret_cast<uint8_t*>(&chain[0]);
      auto* const end = begin + sizeof(Secret);
      std::generate(begin, end, rbe);
      for (size_t i = 1; i < chain.size(); i++) {
        chain[i] = crypto::hash::blake3(chain[i - 1]);
      }
    }

    // We set which secret to use for each chain.
    for (auto& next : next_to_use) {
      next = d - 1;
    }
  }

  Signature sign(uint8_t const* const begin, uint8_t const* const end) {
    Signature signature;
    auto h = crypto::hash::blake3(begin, end);
    for (size_t hash_offset = 0, secret = 0; secret < secrets_per_signature;
         secret++, hash_offset += bits_per_secret) {
      signature[secret] = get_secret(h, hash_offset);
    }
    return signature;
  }

 private:
  friend class PublicKey;
  Chains chains;
  std::array<size_t, t> next_to_use;
  bool worn_out = false;

  Secret& get_secret(Hash const& hash, size_t const byte_offset) {
    auto const secret_index = get_secret_index(hash, byte_offset);
    // fmt::print("Fetching secret with index {}\n", secret_index);
    auto secret_depth = next_to_use[secret_index];
    if (secret_depth > 0) {
      next_to_use[secret_index]--;
      // fmt::print("Will use next secret for {}...\n", secret_index);
    } else {
      worn_out = true;
    }
    // fmt::print("For ({}, {}), the verifier should hash {} to {}.\n",
    // secret_index, secret_depth, chains[secret_index][secret_depth],
    // chains[secret_index][secret_depth + 1]);
    return chains[secret_index][secret_depth];
  }
};

class PublicKey {
 public:
  struct Serialized {
    Serialized() = default;

    std::array<Hash, t> expected_hash;
    std::array<size_t, t> remaining;
  };

  PublicKey(PrivateKey const& private_key) {
    for (size_t i = 0; i < t; i++) {
      expected_hash[i] = private_key.chains[i][private_key.next_to_use[i] + 1];
      remaining[i] = private_key.next_to_use[i];
    }
  }

  PublicKey(Serialized const& serialized_pk) {
    expected_hash = serialized_pk.expected_hash;
    remaining = serialized_pk.remaining;
  }

  Serialized serialize() const { return Serialized{expected_hash, remaining}; }

  template <size_t MessageSize>
  bool verify(SignedMessage<MessageSize> const& signed_message) {
    return verify(signed_message.message.data(),
                  signed_message.message.data() + signed_message.message.size(),
                  signed_message.signature);
  }

  bool verify(uint8_t const* const begin, uint8_t const* const end,
              Signature const& signature) {
    std::array<std::pair<size_t, std::pair<Hash, size_t>>,
               secrets_per_signature - 1>
        backups;  // So that we can restore old values if the verification
                  // fails.
    size_t backed_up = 0;

    auto h = crypto::hash::blake3(begin, end);
    for (size_t hash_offset = 0, secret = 0; secret < secrets_per_signature;
         secret++, hash_offset += bits_per_secret) {
      auto const secret_index = get_secret_index(h, hash_offset);
      if (crypto::hash::blake3(signature[secret]) ==
          expected_hash[secret_index]) {
        // fmt::print("Secret#{} (index {}) matched!\n", secret, secret_index);
        // We back the previous key up.
        // But we only advance keys if we still have more to come.
        if (remaining[secret_index] > 0) {
          [&] {
            if (secret == secrets_per_signature - 1) {
              return;
            }
            for (size_t i = 0; i < backed_up; i++) {
              if (backups[i].first == secret_index) {
                return;
              }
            }
            backups[backed_up++] = {
                secret_index,
                {expected_hash[secret_index], remaining[secret_index]}};
          }();
          // fmt::print("Updated index with secret {}\n", secret_index);
          expected_hash[secret_index] = signature[secret];
          remaining[secret_index]--;
        }
      } else {
        fmt::print(
            "Failed at verifying secret#{} (index {}): hashing {} resulted in "
            "{} which doesn't match {}.\n",
            secret, secret_index, signature[secret],
            crypto::hash::blake3(signature[secret]),
            expected_hash[secret_index]);
        /// debug
        for (size_t i = 0; i < t; i++) {
          if (crypto::hash::blake3(signature[secret]) == expected_hash[i]) {
            fmt::print("But it matched the expected at index {}\n", i);
          }
        }
        /// debug
        // We restore previous keys.
        for (size_t i = 0; i < backed_up; i++) {
          expected_hash[backups[i].first] = backups[i].second.first;
          remaining[backups[i].first] = backups[i].second.second;
        }
        return false;
      }
    }
    return true;
  }

 private:
  std::array<Hash, t> expected_hash;
  std::array<size_t, t> remaining;
};

}  // namespace dory::ubft::pony::horse

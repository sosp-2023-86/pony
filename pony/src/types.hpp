#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include <dory/crypto/asymmetric/dalek.hpp>
#include <dory/crypto/hash/blake3.hpp>
#define crypto_impl dory::crypto::asymmetric::dalek

#include "config.hpp"

#include "export/types.hpp"

namespace dory::pony {

// Bridge the exported types (which have to be self standing) with the internal
// types
static_assert(
    std::is_same_v<EddsaSignature,
                   std::array<uint8_t, crypto_impl::SignatureLength>>);
static_assert(std::is_same_v<Hash, dory::crypto::hash::Blake3Hash>);

using RequestId = size_t;

struct MemoryWindow {
  void* p;
  uint32_t sz;
};

}  // namespace dory::pony

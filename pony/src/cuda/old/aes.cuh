#pragma once

#include <array>
#include <cstdint>

namespace aes256 {

using Key = std::array<uint8_t, 32>;
size_t constexpr BlockSize = 16;  // in bytes

__device__ void encrypt(Key const& key /* seed */, size_t data, void* dst);

}  // namespace aes256

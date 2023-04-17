#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace blake3 {

using Hash = std::array<uint8_t, 32>;

/**
 * @brief Hash an input of Bytes (<= 64) bytes. Optionnally appends the provided
 *        suffix at the end of the input if space is sufficient.
 */
template <size_t Bytes, bool Suffix = false>
__device__ void hash(void const* input, Hash& output, uint32_t suffix = 0);

}  // namespace blake3

#include <cstdint>

#include "blake3.cuh"
#include "blake3.inc"

namespace blake3 {
// Explicit instanciation of hash for 32 and 64 bytes
template __device__ void hash<32, false>(void const* const input, Hash& output,
                                         uint32_t);

template __device__ void hash<32, true>(void const* const input, Hash& output,
                                        uint32_t);

template __device__ void hash<64, false>(void const* const input, Hash& output,
                                         uint32_t);
}  // namespace blake3

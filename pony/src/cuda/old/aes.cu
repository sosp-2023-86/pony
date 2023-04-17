#include <cstdint>

#include "aes.cuh"

namespace aes256 {

using Block = uint8_t[BlockSize];

static __device__ __forceinline__ uint8_t f(uint8_t const x) {
  return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

// S table
__device__ uint8_t constexpr sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

// x-time operation
static __device__ __forceinline__ uint8_t rj_xtime(uint8_t const x) {
  return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x << 1);
}

static __device__ __forceinline__ void sub_bytes(uint8_t* const buf) {
#pragma unroll
  for (int i = 16; i--;) {
    buf[i] = sbox[buf[i]];
  }
}

static __device__ __forceinline__ void add_round_key(uint8_t* const buf,
                                                     uint8_t* const key) {
#pragma unroll
  for (int i = 16; i--;) {
    buf[i] ^= key[i];
  }
}

static __device__ __forceinline__ void add_round_key_and_cpy(
    uint8_t* const buf, uint8_t const* const key, uint8_t* const cpk) {
#pragma unroll
  for (int i = 16; i--;) {
    buf[i] ^= (cpk[i] = key[i]);
    cpk[16 + i] = key[16 + i];
  }
}

static __device__ __forceinline__ void shift_rows(uint8_t* const buf) {
  uint8_t i, j;
  i = buf[1];
  buf[1] = buf[5];
  buf[5] = buf[9];
  buf[9] = buf[13];
  buf[13] = i;
  i = buf[10];
  buf[10] = buf[2];
  buf[2] = i;
  j = buf[3];
  buf[3] = buf[15];
  buf[15] = buf[11];
  buf[11] = buf[7];
  buf[7] = j;
  j = buf[14];
  buf[14] = buf[6];
  buf[6] = j;
}

static __device__ __forceinline__ void mix_columns(uint8_t* const buf) {
  uint8_t i, a, b, c, d, e;
#pragma unroll
  for (i = 0; i < 16; i += 4) {
    a = buf[i];
    b = buf[i + 1];
    c = buf[i + 2];
    d = buf[i + 3];
    e = a ^ b ^ c ^ d;
    buf[i] ^= e ^ rj_xtime(a ^ b);
    buf[i + 1] ^= e ^ rj_xtime(b ^ c);
    buf[i + 2] ^= e ^ rj_xtime(c ^ d);
    buf[i + 3] ^= e ^ rj_xtime(d ^ a);
  }
}

// expand key operation
static __device__ __forceinline__ void expand_key(uint8_t* const k,
                                                  uint8_t* const rc,
                                                  uint8_t const* const sb) {
  k[0] ^= sb[k[29]] ^ (*rc);
  k[1] ^= sb[k[30]];
  k[2] ^= sb[k[31]];
  k[3] ^= sb[k[28]];
  *rc = f(*rc);

#pragma unroll
  for (uint8_t i = 4; i < 16; i += 4) {
    k[i] ^= k[i - 4];
    k[i + 1] ^= k[i - 3];
    k[i + 2] ^= k[i - 2];
    k[i + 3] ^= k[i - 1];
  }

  k[16] ^= sb[k[12]];
  k[17] ^= sb[k[13]];
  k[18] ^= sb[k[14]];
  k[19] ^= sb[k[15]];

#pragma unroll
  for (uint8_t i = 20; i < 32; i += 4) {
    k[i] ^= k[i - 4];
    k[i + 1] ^= k[i - 3];
    k[i + 2] ^= k[i - 2];
    k[i + 3] ^= k[i - 1];
  }
}

/**
 * @brief Encrypts a block consisting of `data` padded.
 *
 */
__device__ void encrypt(Key const& std_key /* seed */, size_t const data,
                        void* const dst) {
  auto const key = reinterpret_cast<uint8_t const*>(
      &std_key);  // std::array not available on device
  // We initialize the state to { data, 0, 0, 0, ... }
  Block state = {};
  *reinterpret_cast<size_t*>(state) = data;
  Key std_round_key;
  auto* const round_key = reinterpret_cast<uint8_t*>(
      &std_round_key);  // std::array not available on device

  add_round_key_and_cpy(state, key, round_key);
  uint8_t rcon = 1;
  for (uint8_t i = 1; i < 14; ++i) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    // Note: in AES256, given that a key is 2x the size of a block/state, and
    //       the round_key can be updated every 2 iterations with the first
    //       half used in odd iterations and the second in even iterations.
    if (i & 1) {
      add_round_key(state, &round_key[16]);
    } else {
      expand_key(round_key, &rcon, sbox);
      add_round_key(state, round_key);
    }
  }
  sub_bytes(state);
  shift_rows(state);
  expand_key(round_key, &rcon, sbox);
  add_round_key(state, round_key);

  /* copy thread buffer back into global memory */
  memcpy(dst, state, BlockSize);
}

}  // namespace aes256

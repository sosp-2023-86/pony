namespace blake3 {

using Block = uint32_t[16];
using V = Block;

enum flags {
  CHUNK_START = 1 << 0,
  CHUNK_END = 1 << 1,
  ROOT = 1 << 3,
};

__device__ uint32_t constexpr ivs[8] = {0x6A09E667, 0xBB67AE85, 0x3C6EF372,
                                        0xA54FF53A, 0x510E527F, 0x9B05688C,
                                        0x1F83D9AB, 0x5BE0CD19};

__device__ uint8_t constexpr sigma[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
    {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13}};

static __device__ __forceinline__ uint rotr32(__const uint w,
                                              __const unsigned c) {
  return (w >> c) | (w << (32 - c));
}

template <size_t Bytes, bool Suffix>
static __device__ __forceinline__ uint32_t word_at(Block const& m,
                                                   uint8_t const index,
                                                   uint32_t const s) {
  if (index < (Bytes >> 2)) {
    // In the provided word.
    return m[index];
  }
  if (index == (Bytes >> 2) && Suffix) {
    // Border and suffix provided
    return s;
  }
  // Padding
  return 0;
}

template <size_t Bytes, bool Suffix>
static __device__ __forceinline__ void g(Block const& m, uint32_t const s,
                                         size_t const r, size_t const i,
                                         uint32_t& a, uint32_t& b, uint32_t& c,
                                         uint32_t& d) {
  // We force bytes above 32 to be 0s. This is optimized at compilation.
  a = a + b + word_at<Bytes, Suffix>(m, sigma[r][2 * i], s);
  d = rotr32(d ^ a, 16);
  c = c + d;
  b = rotr32(b ^ c, 12);
  a = a + b + word_at<Bytes, Suffix>(m, sigma[r][2 * i + 1], s);
  d = rotr32(d ^ a, 8);
  c = c + d;
  b = rotr32(b ^ c, 7);
}

template <size_t Bytes, bool Suffix>
static __device__ __forceinline__ void round(Block const& m, size_t const s,
                                             V& v, size_t const r) {
  g<Bytes, Suffix>(m, s, r, 0, v[0], v[4], v[8], v[12]);
  g<Bytes, Suffix>(m, s, r, 1, v[1], v[5], v[9], v[13]);
  g<Bytes, Suffix>(m, s, r, 2, v[2], v[6], v[10], v[14]);
  g<Bytes, Suffix>(m, s, r, 3, v[3], v[7], v[11], v[15]);
  g<Bytes, Suffix>(m, s, r, 4, v[0], v[5], v[10], v[15]);
  g<Bytes, Suffix>(m, s, r, 5, v[1], v[6], v[11], v[12]);
  g<Bytes, Suffix>(m, s, r, 6, v[2], v[7], v[8], v[13]);
  g<Bytes, Suffix>(m, s, r, 7, v[3], v[4], v[9], v[14]);
}

template <size_t Bytes, bool Suffix>
__device__ void hash(void const* const input, Hash& output,
                     uint32_t const suffix) {
  static_assert(Bytes <= 64);
  static_assert(Bytes % 4 == 0);

  auto const& m = *reinterpret_cast<Block const*>(input);

  V v = {ivs[0],
         ivs[1],
         ivs[2],
         ivs[3],
         ivs[4],
         ivs[5],
         ivs[6],
         ivs[7],

         ivs[0],
         ivs[1],
         ivs[2],
         ivs[3],
         0,                         // t0 chunk index low part
         0,                         // t1 chunk index high part
         Bytes + (Suffix ? 4 : 0),  // number of input bytes in the block
         CHUNK_START | CHUNK_END | ROOT};

  round<Bytes, Suffix>(m, suffix, v, 0);
  round<Bytes, Suffix>(m, suffix, v, 1);
  round<Bytes, Suffix>(m, suffix, v, 2);
  round<Bytes, Suffix>(m, suffix, v, 3);
  round<Bytes, Suffix>(m, suffix, v, 4);
  round<Bytes, Suffix>(m, suffix, v, 5);
  round<Bytes, Suffix>(m, suffix, v, 6);

  auto const output_words = reinterpret_cast<uint32_t*>(&output);

  output_words[0] = v[0] ^ v[8];
  output_words[1] = v[1] ^ v[9];
  output_words[2] = v[2] ^ v[10];
  output_words[3] = v[3] ^ v[11];
  output_words[4] = v[4] ^ v[12];
  output_words[5] = v[5] ^ v[13];
  output_words[6] = v[6] ^ v[14];
  output_words[7] = v[7] ^ v[15];
}
}  // namespace blake3

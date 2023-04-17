#include <fstream>
#include <stdexcept>

#include <dory/crypto/hash/blake3.hpp>

#include "../types.hpp"

namespace dory::pony {

class RandomGenerator {
 public:
  RandomGenerator() {
    std::ifstream random(dev, std::ios::in | std::ios::binary);
    random.read(reinterpret_cast<char*>(seed.data()), sizeof(seed));
    if (!random) {
      throw std::runtime_error("Could not initialize the random seed!");
    }
  }

  Seed generate() {
    // Hash chucks of the seed of size `Blake3Hash` and paste them back to the
    // seed.
    for (size_t i = 0; i < sizeof(seed) / sizeof(crypto::hash::Blake3Hash);
         i++) {
      auto hash_chunk = crypto::hash::blake3(
          seed.begin() + i * sizeof(crypto::hash::Blake3Hash),
          seed.begin() + (i + 1) * sizeof(crypto::hash::Blake3Hash));
      std::copy(hash_chunk.begin(), hash_chunk.end(),
                seed.begin() + i * sizeof(crypto::hash::Blake3Hash));
    }

    size_t elems = sizeof(seed) % sizeof(crypto::hash::Blake3Hash);
    if (elems > 0) {
      // The remaining part of the seed is smaller than the hash.
      size_t remaining_start =
          (sizeof(seed) / sizeof(crypto::hash::Blake3Hash)) *
          sizeof(crypto::hash::Blake3Hash);
      auto hash_chunk =
          crypto::hash::blake3(seed.begin() + remaining_start, seed.end());
      std::copy(hash_chunk.begin(), hash_chunk.begin() + elems,
                seed.begin() + remaining_start);
    }

    return seed;
  }

 private:
  Seed seed;
  static constexpr char const* dev = "/dev/random";
};

}  // namespace dory::pony

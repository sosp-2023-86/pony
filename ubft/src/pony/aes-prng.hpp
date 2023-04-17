#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <dory/shared/branching.hpp>

namespace dory::ubft::pony {

/**
 * @brief A super fast CPRNG based on OpenSSL's AES CTR.
 *
 * A 128-bit seed is generated from OpenSSL's safe randomness and used as an AES
 * key. Then, we cipher a zeroed array using AES in CTR mode to expand the key.
 * The generated randomness has the same level of security as AES-128: 126 bits.
 */
class AesPrng {
  using EvpCipherCtxPtr =
      std::unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;
  static size_t constexpr BlockSize = 16;
  static size_t constexpr KeySize = 16;
  static size_t constexpr IvSize = BlockSize;
  static size_t constexpr CipheredAtOnce = 1 << 13;

 public:
  AesPrng()
      : ctx{EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free},
        to_cipher(CipheredAtOnce, 0u),  // We'll just cipher zeroes.
        ciphered_leftovers(CipheredAtOnce, 0u) {
    // It's important that the key is generated with good randomness.
    std::array<uint8_t, KeySize> key;
    RAND_bytes(key.data(), static_cast<int>(key.size()));
    // My understanding is that the IV doesn't matter, we set it to 0.
    std::array<uint8_t, IvSize> iv = {};
    // We initialize the cipher.
    EVP_EncryptInit(&*ctx, EVP_aes_128_ctr(), key.data(), iv.data());
  }

  void generate(uint8_t* const begin, size_t const length) {
    size_t const iters = length / CipheredAtOnce;
    auto const leftovers = length % CipheredAtOnce;
    uint8_t* out = begin;

    // We fill full blocks.
    for (size_t i = 0; i < iters; i++, out += CipheredAtOnce) {
      int _;  // Encrypted len.
      auto const rc =
          EVP_EncryptUpdate(&*ctx, out, &_, to_cipher.data(), CipheredAtOnce);
      if (unlikely(rc != 1)) {
        throw std::runtime_error("EVP_EncryptUpdate (full blocks) failed");
      }
    }

    // We fill the last bytes.
    if (unlikely(leftovers != 0)) {
      int _;  // Encrypted len.
      auto const rc = EVP_EncryptUpdate(&*ctx, ciphered_leftovers.data(), &_,
                                        to_cipher.data(), CipheredAtOnce);
      if (unlikely(rc != 1)) {
        throw std::runtime_error("EVP_EncryptUpdate (leftovers) failed");
      }
      std::copy(ciphered_leftovers.data(),
                ciphered_leftovers.data() + leftovers, out);
    }
  }

 private:
  EvpCipherCtxPtr ctx;
  std::vector<uint8_t> to_cipher;
  std::vector<uint8_t> ciphered_leftovers;
};

}  // namespace dory::ubft::pony

// Test

// include <chrono>
// include <fmt/core.h>
// include <fmt/chrono.h>
// int main(int argc, char* argv[])
// {
//   using Chrono = std::chrono::steady_clock;
//   dory::ubft::pony::AesPrng prng;
//   std::vector<uint8_t> vector(2000000, 0);
//   for (auto i = 0; i < 100; i++) {
//     auto const start = Chrono::now();
//     prng.generate(vector.data(), vector.size());
//     fmt::print("Generating {}B took {}.\n", vector.size(), Chrono::now() -
//     start);
//   }
// }

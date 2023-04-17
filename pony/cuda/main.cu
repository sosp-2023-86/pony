#include <array>
#include <chrono>
#include <cstdint>
#include <memory>

#include "aes.hpp"
#include "blake3.hpp"
#include "cuda-raii.hpp"
#include "pony.hpp"

static void print_array(void *const p, size_t const bytes) {
  for (int i = 0; i < bytes; i++) {
    printf("%02x", reinterpret_cast<uint8_t *>(p)[i]);
  }
  printf("\n");
}

int main(void) {
  auto sk = makeUniqueCuda<pony::SecretKey>();

  auto seed_host = std::make_unique<pony::Seed>();
  auto seed = makeUniqueCuda<pony::Seed>();
  *seed_host = {};
  cudaUniqueCpy(seed, seed_host);

  {
    auto const start = std::chrono::steady_clock::now();
    sk->populate(seed);
    auto const done = std::chrono::steady_clock::now();
    printf("SK/PK/MT populated in %luns\n",
           std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
               .count());
  }

  auto &pk = sk->public_key;

  {
    auto sk_host_unpinned = std::make_unique<pony::SecretKey>();
    auto const start = std::chrono::steady_clock::now();
    cudaUniqueCpy(sk_host_unpinned, sk);
    auto const done = std::chrono::steady_clock::now();
    printf("Copied SK (unpinned) (%lu bytes) in %luns\n",
           sizeof(pony::SecretKey),
           std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
               .count());
  }

  {
    auto pk_host_pinned = makeUniqueCudaHost<pony::SecretKey>();
    auto const start = std::chrono::steady_clock::now();
    cudaUniqueCpy(pk_host_pinned, sk);
    auto const done = std::chrono::steady_clock::now();
    printf("Copied SK (pinned) (%lu bytes) in %luns\n", sizeof(pony::SecretKey),
           std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
               .count());
  }

  auto sig = makeUniqueCudaHost<pony::Signature>();
  std::array<uint8_t, 7> const msg = {{'h', 'e', 'l', 'l', 'o', '!', 0}};

  // Benchmarking signature + verification
  for (size_t i = 0; i < 1; i++) {
    auto const start = std::chrono::steady_clock::now();
    sk->sign(msg.data(), msg.size(), *sig);
    auto const siged = std::chrono::steady_clock::now();
    auto const ok = pk.check(msg.data(), msg.size(), *sig);
    auto const checked = std::chrono::steady_clock::now();
    printf("Signed in %luns, verified in %luns\n",
           std::chrono::duration_cast<std::chrono::nanoseconds>(siged - start)
               .count(),
           std::chrono::duration_cast<std::chrono::nanoseconds>(checked - siged)
               .count());
  }

  // // DEBUG:
  printf("Seed: ");
  print_array(seed_host.get(), sizeof(pony::Seed));
  for (int i = 0; i < 4; i++) {
    printf("Secret %d: ", i);
    pony::Secret secret;
    cudaMemcpy(&secret, &sk->secrets[i][0], sizeof(pony::Secret),
               cudaMemcpyDeviceToHost);
    print_array(&secret, sizeof(pony::Secret));
    printf("Hash %d: ", i);
    blake3::Hash hash;
    cudaMemcpy(&hash, &pk.hashes[i][0], sizeof(blake3::Hash),
               cudaMemcpyDeviceToHost);
    print_array(&hash, sizeof(blake3::Hash));
  }
  printf("Mt root: ");
  blake3::Hash hash;
  cudaMemcpy(&hash, &pk.merkle_tree.nodes[0], sizeof(blake3::Hash),
             cudaMemcpyDeviceToHost);
  print_array(&hash, sizeof(blake3::Hash));
}

#pragma once

#include <array>

#include <cuda_runtime.h>

#include "aes.cuh"
#include "blake3.cuh"
#include "cuda-raii.cuh"

namespace dory::cuda {

using Seed = aes256::Key;
using Secret = blake3::Hash;

size_t constexpr LogSecretsPerSecretKey = 16;
size_t constexpr SecretsPerSecretKey = 1 << LogSecretsPerSecretKey;

size_t constexpr ThreadsPerBlock = 256;

/**
 * @brief A (templated) struct returned by async functions to easily wait for
 *        their completion.
 *
 * @tparam Streams
 */
template <size_t Streams = 1>
struct Promise {
  std::array<cudaStream_t, Streams> streams;
  bool consummed = false;

  // struct Uninitialized {};
  // Promise(Uninitialized const&) {}

  Promise() {
    for (auto& stream : streams) {
      cudaStreamCreate(&stream);
    }
  }

  // Note: dropping a promise will wait for its completion.
  ~Promise() { wait(); }

  Promise(Promise const&) = delete;
  Promise(Promise&& o) { *this = std::move(o); }
  Promise& operator=(Promise const&) = delete;
  Promise& operator=(Promise&& o) {
    wait();
    std::copy(o.streams.begin(), o.streams.end(), streams.begin());
    consummed = o.consummed;
    o.consummed = true;
    return *this;
  }

  void wait() {
    if (consummed) {
      // throw std::runtime_exception("Was already consummed/moved.");
      return;
    }
    for (auto& stream : streams) {
      cudaStreamDestroy(stream);
    }
    consummed = true;
  }

  cudaStream_t stream() {
    static_assert(Streams == 1);
    return streams[0];
  }
};

// Forward declarations
struct PublicKey;
struct SecretKey;
struct Signature;

struct MerkleTree {
  // Note: the leaves are stored in the PK.
  static size_t constexpr Nodes = SecretsPerSecretKey - 1;
  // static size_t constexpr Levels = 17;

  std::array<blake3::Hash, Nodes> nodes;
  // The leaves are kept in the PK, hence a pointer to it.
  PublicKey const* pk;

  struct Proof {
    // Note: Merkle proofs exclude the root (or the ground in case of forests).
    static size_t constexpr Length = LogSecretsPerSecretKey;
    std::array<blake3::Hash, Length> path;

    /**
     * @brief Checks a merkle proof sequentially.
     */
    __device__ bool check(size_t const leaf_index, blake3::Hash const& leaf,
                          blake3::Hash const& root) const;
  };

  __host__ void populate(PublicKey const* pk);

  using ProofPromise = Promise<Proof::Length>;
  __host__ void prove(size_t const index, Proof& dest, cudaStream_t) const;

  __host__ __device__ inline blake3::Hash const& proof_node(
      size_t leaf_index, size_t level, PublicKey const&) const;
};

struct PublicKey {
  static size_t constexpr Hashes = SecretsPerSecretKey;

  std::array<blake3::Hash, Hashes> hashes;
  MerkleTree merkle_tree;

  __host__ void populate(SecretKey const& sk);

  __host__ bool check(uint8_t const* msg, size_t msg_len, Signature const& sig);
};

struct SecretKey {
  static size_t constexpr LogSecrets = LogSecretsPerSecretKey;
  static size_t constexpr Secrets = SecretsPerSecretKey;
  std::array<Secret, Secrets> secrets;
  PublicKey public_key;

  __host__ void populate(UniqueCudaPtr<Seed> const& seed);

  __host__ void sign(uint8_t const* msg, size_t msg_len, Signature&) const;
};

struct Signature {
  static size_t constexpr Secrets = 16;

  struct ProvedSecret {
    Secret secret;
    MerkleTree::Proof proof;
  };

  std::array<uint8_t, 64> eddsa;
  blake3::Hash root;
  std::array<ProvedSecret, Secrets> secrets;

  __host__ bool check(uint8_t const& msg, size_t msg_len);
};

/**
 * @brief A hash generated from the concatenation of multiple hashes and used to
 *        know which secrets to reveal.
 *
 * A single hash may not be enough to extract k index.
 * We thus need to generate an extended hash (i.e., a combination of multiple
 * hashes).
 */
class ExtendedHash {
 public:
  ExtendedHash() = default;
  ExtendedHash(uint8_t const* const msg, size_t const msg_len);

  __device__ __host__ inline size_t secret_index(size_t total_bit_offset) const;

 private:
  std::array<uint8_t, (LogSecretsPerSecretKey * Signature::Secrets + 7) / 8>
      hash;
};

}  // namespace dory::cuda

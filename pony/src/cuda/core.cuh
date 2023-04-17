#pragma once

#include <algorithm>
#include <array>
#include <optional>
#include <type_traits>

#include <cuda_runtime.h>

#include <dory/crypto/hash/blake3.hpp>

#include <fmt/ranges.h>

#include "../config.hpp"
#include "../types.hpp"

#include "alloc.cuh"
#include "blake3.cuh"
#include "util.cuh"

namespace dory::cuda {
using Seed = pony::Seed;
using Secret = blake3::Hash;
static_assert(std::is_same_v<Secret, pony::Secret>,
              "CPU and GPU implementation of blake3 should match");

size_t constexpr ThreadsPerBlock = 256;

struct MemoryWindow {
  void* p;
  size_t sz;
};

struct SecretKeyInternal {
  static size_t constexpr Secrets = pony::SecretsPerSecretKey;
  static size_t constexpr SecretsDepth = pony::SecretsDepth;

  Seed seed_h;
  UninitializedUniqueCudaPtr<
      std::array<std::array<Secret, Secrets>, SecretsDepth>>
      secrets_d;
  InitializedUniqueHostPtr<
      std::array<std::array<Secret, Secrets>, SecretsDepth>>
      secrets_h;

  SecretKeyInternal(Seed seed, HostAllocator& host_alloc,
                    DeviceAllocator& gpu_alloc);

  bool verifyCpuData() {
    static_assert(
        std::is_same_v<Seed, std::array<uint8_t, 32>>,
        "Types are incompatible. Adjust types or rewrite the CPU version");

    // Hash the seed (32 bytes) extended by the uint32_t (4 bytes)
    size_t constexpr extended_secret_len = sizeof(Seed) + sizeof(uint32_t);
    std::array<uint8_t, extended_secret_len> padded_seed;
    std::fill(padded_seed.begin(), padded_seed.end(), 0);
    std::copy(seed_h.begin(), seed_h.end(), padded_seed.begin());
    uint32_t* padding =
        reinterpret_cast<uint32_t*>(padded_seed.data() + sizeof(Seed));

    // fmt::print("Seed       : {}\n", seed_h);
    // fmt::print("Padded_seed: {}\n", padded_seed);

    // Verifying the root secrets.
    uint32_t padding_num = 0;
    for (auto const& hash : secrets_h->front()) {
      // fmt::print("Secret_h: {}\n", hash);
      *padding = padding_num;

      auto cpu_hash = crypto::hash::blake3(
          padded_seed.begin(), padded_seed.begin() + extended_secret_len);

      // fmt::print("cpu_secr: {}\n", cpu_hash);

      if (cpu_hash != hash) {
        return false;
      }

      padding_num++;
    }

    // Verifying the grid.
    for (size_t i = 0; i < Secrets; i++) {
      for (size_t j = 1; j < SecretsDepth; j++) {
        if ((*secrets_h)[j][i] !=
            crypto::hash::blake3((*secrets_h)[j - 1][i])) {
          return false;
        }
      }
    }

    return true;
  }

  void resetSeed(Seed const& seed) { seed_h = seed; }
  Seed const& getSeed() const { return seed_h; }
  void schedulePopulate(cudaStream_t& stream);
  void scheduleCopyBack(cudaStream_t& stream);
};

struct PublicKeyInternal {
  static size_t constexpr Hashes = pony::SecretsPerSecretKey;
  struct WotsVerificationIO {
    // Note: we use SecretsPerSignature instead of SecretsPerSecretKey as they
    //       do not match when using Hors, which causes a compilation error.
    std::array<Secret, pony::SecretsPerSignature> secrets;
    std::array<size_t, pony::SecretsPerSignature> nb_hashes;
    bool valid;
  };

  SecretKeyInternal* sk;

  UninitializedUniqueCudaPtr<pony::PublicKey> eddsa_hashes_d;
  InitializedUniqueHostPtr<pony::PublicKey> eddsa_hashes_h;

  UninitializedUniqueCudaPtr<WotsVerificationIO> wots_io_d;

  PublicKeyInternal(SecretKeyInternal* sk, HostAllocator& host_alloc,
                    DeviceAllocator& gpu_alloc);

  bool verifyCpuData() {
    size_t idx = 0;
    for (auto const& secret : sk->secrets_h->back()) {
      auto cpu_hash = crypto::hash::blake3(secret.begin(), secret.end());
      if (cpu_hash != eddsa_hashes_h->hashes.at(idx)) {
        return false;
      }

      idx++;
    }

    return true;
  }

  void schedulePopulate(cudaStream_t& stream);
  void scheduleCopy(cudaStream_t& stream);
  void scheduleCopyBack(cudaStream_t& stream);

  bool verify(pony::WotsSignature const& sig, uint8_t const* msg,
              size_t const msg_len, cudaStream_t& stream);
};

struct MerkleTreeInternal {
  static size_t constexpr Nodes = pony::SecretsPerSecretKey - 1;
  // static size_t constexpr Levels = 17;

  PublicKeyInternal const* pk;

  UninitializedUniqueCudaPtr<std::array<blake3::Hash, Nodes>> nodes_d;
  InitializedUniqueHostPtr<std::array<blake3::Hash, Nodes>> nodes_h;

  MerkleTreeInternal(PublicKeyInternal* pk, HostAllocator& host_alloc,
                     DeviceAllocator& gpu_alloc);

  bool verifyCpuData() {
    auto const first_root_index = pony::hors::NbRoots - 1;
    for (auto root = first_root_index;
         root < first_root_index + pony::hors::NbRoots; root++) {
      // fmt::print("Checking the MT at node {}. Overall, there are {} nodes\n",
      // idx, 2 * pk->hashes_d->size() - 1);
      auto cpu_root =
          check_recursively(root, 2 * pk->eddsa_hashes_d->hashes.size() - 1);
      // fmt::print("The cpu hash at root {} is {}\n", idx, cpu_root);
      // fmt::print("The gpu hash at root {} is {}\n", idx, nodes_h->at(idx));

      if (cpu_root != nodes_h->at(root)) {
        return false;
      }
    }

    return true;
  }

  void schedulePopulate(cudaStream_t& stream);
  void scheduleCopyBack(cudaStream_t& stream);

 private:
  crypto::hash::Blake3Hash check_recursively(size_t root, size_t overall_size) {
    std::array<uint8_t, 64> combined;

    if (root >= overall_size / 4) {
      // fmt::print("Accessing element {} from PK\n", (2 * root + 1) + 1 -
      // pk->eddsa_hashes_h->hashes.size());
      auto left_leaf = pk->eddsa_hashes_h->hashes.at(
          (2 * root + 1) + 1 - pk->eddsa_hashes_h->hashes.size());
      std::copy(left_leaf.begin(), left_leaf.end(), combined.begin());

      // fmt::print("Accessing element {} from PK\n", (2 * root + 2) + 1 -
      // pk->eddsa_hashes_h->hashes.size());
      auto right_leaf = pk->eddsa_hashes_h->hashes.at(
          (2 * root + 2) + 1 - pk->eddsa_hashes_h->hashes.size());
      std::copy(right_leaf.begin(), right_leaf.end(), combined.begin() + 32);

      return crypto::hash::blake3(combined.begin(), combined.end());
    }

    // fmt::print("Unreachable\n");
    auto left_hash = check_recursively(2 * root + 1, overall_size);
    auto right_hash = check_recursively(2 * root + 2, overall_size);
    std::copy(left_hash.begin(), left_hash.end(), combined.begin());
    std::copy(right_hash.begin(), right_hash.end(), combined.begin() + 32);

    return crypto::hash::blake3(combined.begin(), combined.end());
  }
};

class SignerVerifierBase {
 private:
  struct CudaContext {
    CudaContext() {
      gpuErrchk(cudaStreamCreate(&compute_stream));
      gpuErrchk(cudaEventCreate(&stop_event));
    }

    ~CudaContext() {
      gpuErrchk(cudaEventDestroy(stop_event));
      gpuErrchk(cudaStreamDestroy(compute_stream));
    }

    void resetStopEvent() { gpuErrchk(cudaEventCreate(&stop_event)); }

    void recordStopEvent() {
      gpuErrchk(cudaEventRecord(stop_event, compute_stream));
    }

    bool eventTriggered() {
      cudaError_t result = cudaEventQuery(stop_event);
      if (result == cudaSuccess) {
        return true;
      } else if (result == cudaErrorNotReady) {
        return false;
      }

      throw std::runtime_error(
          fmt::format("CUDA Runtime Error: {}\n", cudaGetErrorString(result)));
    }

    CudaContext(CudaContext const& other) = delete;
    CudaContext& operator=(CudaContext const& other) = delete;

    CudaContext(CudaContext&& other) = delete;
    CudaContext& operator=(CudaContext&& other) = delete;

    cudaStream_t compute_stream;
    cudaEvent_t stop_event;
  };

 public:
  SignerVerifierBase() = default;

 protected:
  CudaContext cuda_ctx;
};
}  // namespace dory::cuda

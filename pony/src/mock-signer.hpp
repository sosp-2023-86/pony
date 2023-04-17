#pragma once

#include <cstddef>
#include <cstdint>

#include <dory/crypto/hash/blake3.hpp>

#include "alloc.hpp"
#include "sk/offload.hpp"
#include "types.hpp"

namespace dory::pony {
class CpuMockSigner : public SkOffload {
  static size_t constexpr Nodes = SecretsPerSecretKey - 1;
  using Hash = crypto::hash::Blake3Hash;

 public:
  CpuMockSigner(Seed const &seed, cuda::HostAllocator &host_alloc)
      : secrets{cuda::makeInitializedUniqueHost<
            std::array<Secret, SecretsPerSecretKey>>(host_alloc)},
        eddsa_hashes{cuda::makeInitializedUniqueHost<PublicKey>(host_alloc)},
        nodes{cuda::makeInitializedUniqueHost<std::array<Hash, Nodes>>(
            host_alloc)} {}

  void reset(Seed const &s) override { seed = s; }

  Seed const &getSeed() const override { return seed; }

  void scheduleCompute() override {
    generate_secrets();
    generate_public_key();
    generate_merkle_tree();
  }

  bool validSecretKey() override { return true; }  // replace

  bool validPublicKey() override { return true; }  // replace

  bool validMerkleRoots() override { return true; }  // replace

  bool ready() override { return true; }

  MemoryWindow memoryWindow(MemoryWindowKind kind,
                            MemoryWindowDevice device) override {
    switch (kind) {
      case SK:
        if (device == Host) {
          return MemoryWindow{secrets->data(),
                              static_cast<uint32_t>(sizeof(*secrets))};
        } else {
          throw std::runtime_error("Unsupported operation!");
        }
      case PK:
        if (device == Host) {
          return MemoryWindow{eddsa_hashes.get(),
                              static_cast<uint32_t>(sizeof(*eddsa_hashes))};
        } else {
          throw std::runtime_error("Unsupported operation!");
        }
      case MT:
        if (device == Host) {
          return MemoryWindow{nodes->data(),
                              static_cast<uint32_t>(sizeof(*nodes))};
        } else {
          throw std::runtime_error("Unsupported operation!");
        }
      default:
        throw std::runtime_error("Unreachable!");
    }
  }

  void generate_secrets() {
    static_assert(
        std::is_same_v<Seed, std::array<uint8_t, 32>>,
        "Types are incompatible. Adjust types or rewrite the CPU version");

    // Hash the seed (32 bytes) extended by the uint32_t (4 bytes)
    size_t constexpr extended_secret_len = sizeof(Seed) + sizeof(uint32_t);
    std::array<uint8_t, extended_secret_len> padded_seed;
    std::fill(padded_seed.begin(), padded_seed.end(), 0);
    std::copy(seed.begin(), seed.end(), padded_seed.begin());
    uint32_t *padding =
        reinterpret_cast<uint32_t *>(padded_seed.data() + sizeof(Seed));

    uint32_t padding_num = 0;
    for (auto &hash : *secrets) {
      *padding = padding_num;

      hash = crypto::hash::blake3(padded_seed.begin(),
                                  padded_seed.begin() + extended_secret_len);

      padding_num++;
    }
  }

  void generate_public_key() {
    size_t idx = 0;
    for (auto const &secret : *secrets) {
      eddsa_hashes->hashes.at(idx) =
          crypto::hash::blake3(secret.begin(), secret.end());
      idx++;
    }
  }

  void generate_merkle_tree() {
    int level_limit = static_cast<int>(hors::LogNbRoots);

    for (size_t idx = 0; idx < SecretsPerSecretKey; idx += 2) {
      auto adapted_idx = SecretsPerSecretKey - 1 + idx;
      auto parent = (adapted_idx - 1) / 2;
      auto *start = reinterpret_cast<uint8_t *>(&eddsa_hashes->hashes.at(idx));
      nodes->at(parent) = crypto::hash::blake3(start, start + 2 * sizeof(Hash));
    }

    for (int level = hors::LogSecretsPerSecretKey - 1; level > level_limit;
         level--) {
      for (size_t idx = (1UL << level) - 1; idx < ((1UL << (level + 1)) - 1);
           idx += 2) {
        auto parent = (idx - 1) / 2;
        auto *start = reinterpret_cast<uint8_t *>(&nodes->at(idx));
        nodes->at(parent) =
            crypto::hash::blake3(start, start + 2 * sizeof(Hash));
      }
    }
  }

 private:
  Seed seed;
  cuda::InitializedUniqueHostPtr<std::array<Secret, SecretsPerSecretKey>>
      secrets;
  cuda::InitializedUniqueHostPtr<PublicKey> eddsa_hashes;
  cuda::InitializedUniqueHostPtr<std::array<Hash, Nodes>> nodes;
};
}  // namespace dory::pony

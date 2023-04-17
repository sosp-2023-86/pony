#pragma once

#include <cstddef>
#include <cstdint>

#include <dory/crypto/hash/blake3.hpp>

#include <fmt/core.h>

#include "alloc.hpp"
#include "sk/offload.hpp"
#include "types.hpp"

namespace dory::pony {
class CpuMockVerifier : public PkOffload {
  static size_t constexpr Nodes = SecretsPerSecretKey - 1;
  using Hash = crypto::hash::Blake3Hash;

 public:
  CpuMockVerifier(cuda::HostAllocator &host_alloc)
      : eddsa_hashes{cuda::makeInitializedUniqueHost<PublicKey>(host_alloc)},
        nodes{cuda::makeInitializedUniqueHost<std::array<Hash, Nodes>>(
            host_alloc)} {}

  void reset() override {}

  void scheduleCompute() override { generate_merkle_tree(); }

  bool validMerkleRoots() override { return true; }  // replace

  bool ready() override { return true; }

  bool verify(WotsSignature const &sig, uint8_t const *msg,
              size_t const msg_len) override {
    return true;
  };

  MemoryWindow memoryWindow(MemoryWindowKind kind,
                            MemoryWindowDevice device) override {
    switch (kind) {
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

 private:
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

  cuda::InitializedUniqueHostPtr<PublicKey> eddsa_hashes;
  cuda::InitializedUniqueHostPtr<std::array<Hash, Nodes>> nodes;
};
}  // namespace dory::pony

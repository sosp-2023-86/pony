#pragma once

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include <fmt/core.h>
#include <fmt/ranges.h>

#include <dory/memstore/store.hpp>
#include <dory/shared/logger.hpp>

#include "config.hpp"
#include "types.hpp"

#include "alloc.hpp"
#include "cuda-check.hpp"
#include "cuda-signer.hpp"
#include "cuda-verifier.hpp"

// Use Dalek or Sodium
#include <dory/crypto/asymmetric/dalek.hpp>
#define crypto_impl dory::crypto::asymmetric::dalek

// #include <dory/crypto/asymmetric/sodium.hpp>
// #define crypto_impl dory::crypto::asymmetric::sodium

namespace dory::pony {
class EddsaCrypto {
 public:
  using Signature = std::array<uint8_t, crypto_impl::SignatureLength>;

  EddsaCrypto(ProcId local_id, std::vector<ProcId> const &all_ids)
      : my_id{local_id}, store{nspace}, LOGGER_INIT(logger, "Pony") {
    crypto_impl::init();

    LOGGER_INFO(logger, "Publishing my EdDSA key (process {})", my_id);
    crypto_impl::publish_pub_key(fmt::format("{}-pubkey", local_id));

    LOGGER_INFO(logger, "Waiting for all processes ({}) to publish their keys",
                all_ids);
    store.barrier("public_keys_announced", all_ids.size());

    for (auto id : all_ids) {
      public_keys.emplace(
          id, crypto_impl::get_public_key(fmt::format("{}-pubkey", id)));
    }
  }

  inline Signature sign(uint8_t const *msg,      // NOLINT
                        size_t const msg_len) {  // NOLINT
    Signature sig;
    crypto_impl::sign(sig.data(), msg, msg_len);
    return sig;
  }

  inline bool verify(Signature const &sig, uint8_t const *msg,
                     size_t const msg_len, ProcId const node_id) {
    auto pk_it = public_keys.find(node_id);
    if (pk_it == public_keys.end()) {
      throw std::runtime_error(
          fmt::format("Missing public key for {}!", node_id));
    }

    return crypto_impl::verify(sig.data(), msg, msg_len, pk_it->second);
  }

  inline bool verify(BatchedEddsaSignature const &sig, ProcId const node_id) {
    auto const *const roots_hashes =
        reinterpret_cast<uint8_t const *>(&sig.hashes);
    return verify(sig.sig, roots_hashes, sizeof(sig.hashes), node_id);
  }

  inline ProcId myId() const { return my_id; }

 private:
  ProcId const my_id;
  memstore::MemoryStore store;

  // Map: NodeId (ProcId) -> Node's Public Key
  std::unordered_map<ProcId, crypto_impl::pub_key> public_keys;
  LOGGER_DECL(logger);
};

class CudaCrypto {
 public:
  CudaCrypto(cuda::HostAllocator &host_alloc, cuda::DeviceAllocator &gpu_alloc)
      : host_alloc{host_alloc}, gpu_alloc{gpu_alloc} {}

  bool gpuWorks() { return cuda_works(false); }

  void run(bool measure_time = true) {
    Seed seed{};

    std::chrono::time_point<std::chrono::steady_clock> start, done;

    if (measure_time) {
      start = std::chrono::steady_clock::now();
    }
    CudaSigner signer(seed, host_alloc, gpu_alloc);
    CudaVerifier verifier(host_alloc, gpu_alloc);
    if (measure_time) {
      done = std::chrono::steady_clock::now();
      fmt::print(
          "CudaSigner constructed in {}ns\n",
          std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
              .count());
    }

    for (int i = 0; i < 10; i++) {
      if (measure_time) {
        start = std::chrono::steady_clock::now();
      }
      signer.scheduleCompute();
      while (!signer.ready()) {
      }
      if (measure_time) {
        done = std::chrono::steady_clock::now();
        fmt::print(
            "CudaSigner computed in {}ns\n",
            std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
                .count());
      }

      fmt::print(
          "Signer: the SK generated in the GPU/copied to the CPU {} the "
          "version generated in the CPU\n",
          signer.validSecretKey() ? "matches" : "DOES NOT match");
      fmt::print(
          "Signer: the PK generated in the GPU/copied to the CPU {} the "
          "version generated in the CPU\n",
          signer.validPublicKey() ? "matches" : "DOES NOT match");
      fmt::print(
          "Signer: the MT roots generated in the GPU/copied to the CPU {} the "
          "version generated in the CPU\n",
          signer.validMerkleRoots() ? "match" : "DO NOT match");

      if (measure_time) {
        start = std::chrono::steady_clock::now();
      }
      // Emulate RDMA
      auto [from_ptr, from_sz] =
          signer.memoryWindow(CudaSigner::PK, CudaSigner::Host);
      auto [to_ptr, to_sz] =
          verifier.memoryWindow(CudaVerifier::PK, CudaVerifier::Host);
      std::memcpy(to_ptr, from_ptr, from_sz);
      if (measure_time) {
        done = std::chrono::steady_clock::now();
        fmt::print(
            "Emulated RDMA copy from Host memory to Host memory {}ns\n",
            std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
                .count());
      }

      if (measure_time) {
        start = std::chrono::steady_clock::now();
      }
      verifier.scheduleCompute();
      while (!verifier.ready()) {
      }
      if (measure_time) {
        done = std::chrono::steady_clock::now();
        fmt::print(
            "CudaVerifier computed in {}ns\n",
            std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
                .count());
      }

      fmt::print(
          "Verifier: the MT roots generated in the GPU/copied to the CPU {} the"
          " version generated in the CPU\n",
          verifier.validMerkleRoots() ? "match" : "DO NOT match");

      if (measure_time) {
        start = std::chrono::steady_clock::now();
      }
      seed[0] = static_cast<uint8_t>(i);
      signer.reset(seed);
      if (measure_time) {
        done = std::chrono::steady_clock::now();
        fmt::print(
            "CudaSigner reset in {}ns\n",
            std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
                .count());
      }

      if (measure_time) {
        start = std::chrono::steady_clock::now();
      }
      verifier.reset();
      if (measure_time) {
        done = std::chrono::steady_clock::now();
        fmt::print(
            "CudaVerifier reset in {}ns\n",
            std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
                .count());
      }

      fmt::print("\n");
    }
  }

 private:
  cuda::HostAllocator &host_alloc;
  cuda::DeviceAllocator &gpu_alloc;
};
}  // namespace dory::pony

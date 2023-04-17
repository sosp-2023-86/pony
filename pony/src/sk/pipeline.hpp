#pragma once

#include <deque>
#include <exception>
#include <map>
#include <memory>
#include <vector>

#include <dory/shared/logger.hpp>

#include "../alloc.hpp"
#include "../config.hpp"
#include "../crypto.hpp"
#include "../cuda-check.hpp"
#include "../mutex.hpp"
#include "../rc.hpp"
#include "../signer.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include "context.hpp"
#include "cpu-workers.hpp"
#include "random.hpp"

namespace dory::pony {

class SkPipeline {
 public:
  SkPipeline(PonyRcs& rcs, EddsaCrypto& eddsa, cuda::HostAllocator& host_alloc,
             cuda::DeviceAllocator& gpu_alloc)
      : rcs{rcs}, cpu_workers{eddsa}, LOGGER_INIT(logger, "Pony::SkPipeline") {
    bool cpu_mock = !cuda::have_gpu();

    for (size_t i = 0; i < SkCtxs; i++) {
      auto seed = seed_generator.generate();
      LOGGER_DEBUG(logger, "Creating context {} with seed: {}", i, seed);

      std::unique_ptr<SkOffload> offload;
      if (cpu_mock) {
        offload = std::make_unique<CpuMockSigner>(seed, host_alloc);
      } else {
        offload = std::make_unique<CudaSigner>(seed, host_alloc, gpu_alloc);
      }

      free_sks.emplace_back(std::make_unique<SkContext>(
          std::move(offload), rcs.remote_ids.size(), i));
    }
  }

  SkPipeline(SkPipeline const&) = delete;
  SkPipeline& operator=(SkPipeline const&) = delete;
  SkPipeline(SkPipeline&&) = delete;
  SkPipeline& operator=(SkPipeline&&) = delete;

  void tick() {
    recycle_worn_out_sks();
    schedule_new_sks();
    manage_offloads();
  }

  std::unique_ptr<SkContext> extract_ready() {
    // The sks should mostly get ready in order.
    if (offloaded_sks.empty() ||
        offloaded_sks.front()->state != SkContext::Ready) {
      return nullptr;
    }
    auto sk = std::move(offloaded_sks.front());
    offloaded_sks.pop_front();
    LOGGER_TRACE(logger, "{} extracted", sk->to_string());
    return sk;
  }

  void recycle(std::unique_ptr<SkContext>&& sk) {
    sk->move_to(SkContext::WornOut, profilers);
    LOGGER_TRACE(logger, "{} scheduled to be recycled", sk->to_string());
    std::scoped_lock<Mutex> wo_lock(worn_out_sks_mutex);
    worn_out_sks.emplace_back(std::move(sk));
  }

  void report_latencies() {
    for (auto const state :
         {SkContext::ComputingKeysAndTree, SkContext::ComputingEddsa,
          SkContext::ToSend, SkContext::Ready}) {
      LOGGER_INFO(logger, "Time spent in {}:", SkContext::to_string(state));
      profilers[state].report();
    }
  }

 private:
  void recycle_worn_out_sks() {
    rcs.poll_send();
    // A lock is required as worn out sks are returned by the app thread.
    std::scoped_lock<Mutex> wo_lock(worn_out_sks_mutex);

    while (!worn_out_sks.empty()) {
      auto& sk = worn_out_sks.front();
      // We can only schedule again contexts that have been acked by everyone.
      if (!sk->can_reuse_buffer()) {
        // If it's not the case, we move the sk to the back.
        // LOGGER_INFO(logger, "Worn out sk {} not fully acked ({} out of {}).",
        //             sk->id, sk->acks, sk->max_acks);
        worn_out_sks.emplace_back(std::move(sk));
        worn_out_sks.pop_front();
        // And we return not to loop forever.
        return;
      }
      // Otherwise we move it to the free list.
      free_sks.emplace_back(std::move(sk));
      worn_out_sks.pop_front();
      // We release the lock to minimize the critical section.
      worn_out_sks_mutex.unlock();

      auto& fsk = *free_sks.back();
      auto seed = seed_generator.generate();
      fsk.reset(seed);
      LOGGER_TRACE(logger, "{} recycled with seed {}", fsk.to_string(), seed);

      // And don't forget to tkae the lock back for the loop check.
      worn_out_sks_mutex.lock();
    }
  }

  void schedule_new_sks() {
    for (; gpu_credits > 0 && !free_sks.empty(); gpu_credits--) {
      auto& sk = free_sks.front();

      sk->move_to(SkContext::ComputingKeysAndTree, profilers);
      sk->offload->scheduleCompute();
      LOGGER_TRACE(logger, "{} Free -> ComputingKeysAndTree", sk->to_string());

      // On-CPU version
      // auto& skm = *reinterpret_cast<std::array<Secret,
      // SecretsPerSecretKey>*>(sk->offload->memoryWindow(CudaSigner::SK,
      // CudaSigner::Host).p); auto& pkm =
      // *reinterpret_cast<PublicKey*>(sk->offload->memoryWindow(CudaSigner::PK,
      // CudaSigner::Host).p); auto hasher = dory::crypto::hash::blake3_init();
      // dory::crypto::hash::blake3_update(hasher, 1);
      // dory::crypto::hash::blake3_final_there(hasher, skm[0].data(),
      // sizeof(skm)); for (size_t i = 0; i < pkm.hashes.size(); i++) {
      //   pkm.hashes[i] = dory::crypto::hash::blake3(skm[i]);
      // }

      offloaded_sks.emplace_back(std::move(sk));
      free_sks.pop_front();
    }
  }

  void manage_offloads() {
    for (auto& sk : offloaded_sks) {
      if (sk->state == SkContext::Free) {
        throw std::logic_error("Free SK in offloaded list.");
      }
      if (sk->state == SkContext::ComputingKeysAndTree) {
        if (sk->offload->ready()) {
          gpu_credits++;
          if constexpr (Scheme == HORS && hors::PkEmbedding == hors::Merkle) {
            LOGGER_DEBUG(
                logger, "Signer: MT checksum {}",
                logging::memory_window_checksum(sk->offload->memoryWindow(
                    CudaSigner::MT, CudaSigner::Host)));
            LOGGER_DEBUG(
                logger,
                "Signer: the MT roots generated in the GPU/copied to the CPU "
                "{} "
                "the version generated in the CPU",
                sk->offload->validMerkleRoots() ? "match" : "DO NOT match");
          }

          sk->move_to(SkContext::ComputingEddsa, profilers);
          cpu_workers.schedule_sign(*sk);
          LOGGER_TRACE(logger, "{} ComputingKeysAndTree -> ComputingEddsa",
                       sk->to_string());
        }
      }
      if (sk->state == SkContext::ComputingEddsa) {
        if (sk->eddsa_computed) {
          sk->move_to(SkContext::ToSend, profilers);
          LOGGER_TRACE(logger, "{} ComputingEddsa -> ToSend", sk->to_string());
        }
      }
      if (sk->state == SkContext::ToSend) {
        rcs.poll_send();
        if (rcs.try_send(*sk)) {
          sk->move_to(SkContext::Ready, profilers);
          LOGGER_TRACE(logger, "{} ToSend -> Ready", sk->to_string());
        }
      }
    }
  }

  std::deque<std::unique_ptr<SkContext>> free_sks;
  std::deque<std::unique_ptr<SkContext>> offloaded_sks;
  std::deque<std::unique_ptr<SkContext>> worn_out_sks;
  Mutex worn_out_sks_mutex;
  size_t gpu_credits = 4;

  PonyRcs& rcs;
  SkCpuWorkers cpu_workers;
  RandomGenerator seed_generator;

  // Latency measurement
  SkContext::Profilers profilers;

  LOGGER_DECL(logger);
};

}  // namespace dory::pony

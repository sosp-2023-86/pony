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
#include "../latency.hpp"
#include "../rc.hpp"
#include "../types.hpp"
#include "../util.hpp"
#include "../verifier.hpp"
#include "context.hpp"
#include "cpu-workers.hpp"

namespace dory::pony {

class PkPipeline {
 public:
  PkPipeline(PonyRcs &rcs, EddsaCrypto &eddsa, cuda::HostAllocator &host_alloc,
             cuda::DeviceAllocator &gpu_alloc)
      : rcs{rcs}, cpu_workers{eddsa}, LOGGER_INIT(logger, "Pony::PkPipeline") {
    for (auto const &id : rcs.remote_ids) {
      armed_pks.try_emplace(id);
      auto &free_pk_queue = free_pks.try_emplace(id).first->second;
      // fmt::print("Emplaced free queue for {}\n", id);
      // We need to create more pks than buffered keys so that we are always
      // armed to receive new keys.

      bool cpu_mock = !cuda::have_gpu();

      for (size_t i = 0; i < PkCtxsPerProcess; i++) {
        std::unique_ptr<PkOffload> offload;
        if (cpu_mock) {
          offload = std::make_unique<CpuMockVerifier>(host_alloc);
        } else {
          offload = std::make_unique<CudaVerifier>(host_alloc, gpu_alloc);
        }

        free_pk_queue.emplace_back(
            std::make_unique<PkContext>(id, std::move(offload), i));
      }
    }
  }

  PkPipeline(PkPipeline const &) = delete;
  PkPipeline &operator=(PkPipeline const &) = delete;
  PkPipeline(PkPipeline &&) = delete;
  PkPipeline &operator=(PkPipeline &&) = delete;

  void tick() {
    arm_new_pks();
    poll_armed_pks();
    manage_offloads();
  }

  std::unique_ptr<PkContext> extract_ready() {
    // We discard all invalid keys, no need to recycle them as their signer is
    // Byzantine.
    while (!offloaded_pks.empty() &&
           offloaded_pks.front()->state == PkContext::Invalid) {
      offloaded_pks.pop_front();
    }
    // The pks should mostly get ready in order.
    if (offloaded_pks.empty() ||
        offloaded_pks.front()->state != PkContext::Ready) {
      return nullptr;
    }
    auto pk = std::move(offloaded_pks.front());
    offloaded_pks.pop_front();
    LOGGER_TRACE(logger, "{} extracted", pk->to_string());
    return pk;
  }

  void recycle(std::unique_ptr<PkContext> &&pk) {
    pk->reset();
    LOGGER_TRACE(logger, "{} recycled", pk->to_string());
    free_pks[pk->signer].emplace_back(std::move(pk));
  }

  void report_latencies() {
    for (auto const state : {PkContext::Armed, PkContext::ComputingTree,
                             PkContext::VerifyingEddsa}) {
      LOGGER_INFO(logger, "Time spent in {}:", PkContext::to_string(state));
      profilers[state].report();
    }
  }

 private:
  void arm_new_pks() {
    for (auto &[id, free_pk_queue] : free_pks) {
      while (!free_pk_queue.empty()) {
        auto &pk = free_pk_queue.front();
        if (!rcs.try_arm_recv(*pk)) {
          break;
        }
        pk->move_to(PkContext::Armed, profilers);
        LOGGER_TRACE(logger, "{} Free -> Armed", pk->to_string());
        armed_pks[id].emplace_back(std::move(pk));
        free_pk_queue.pop_front();
      }
    }
  }

  void poll_armed_pks() {
    for (PkContext *pk = nullptr; gpu_credits > 0 && (pk = rcs.try_poll_recv());
         gpu_credits--) {
      pk->move_to(PkContext::ComputingTree, profilers);

#if SPDLOG_ACTIVE_LEVEL <= SPDLOG_LEVEL_DEBUG
      auto const pk_addr =
          pk->offload->memoryWindow(PkOffload::PK, PkOffload::Host).p;
      auto const pk_size = SentPkPrefix;

      LOGGER_DEBUG(logger, "Receiving PK. Length {} bytes, {}", pk_size,
                   logging::public_key(pk_addr));
#endif

      pk->offload->scheduleCompute();
      LOGGER_TRACE(logger, "{} Armed -> ComputingTree", pk->to_string());

      auto const signer = pk->signer;
      auto &armed_pk_queue = armed_pks[signer];
      // The FIFO-ness of RCs should guarantee that this is the first pk.
      if (armed_pk_queue.front().get() != pk) {
        throw std::logic_error("The recvd pk should be the first one.");
      }
      offloaded_pks.emplace_back(std::move(armed_pk_queue.front()));
      armed_pk_queue.pop_front();
    }
  }

  void manage_offloads() {
    for (auto &pk : offloaded_pks) {
      if (pk->state == PkContext::Free) {
        throw std::logic_error("Free PK in offloaded list.");
      }
      if (pk->state == PkContext::ComputingTree) {
        if (pk->offload->ready()) {
          gpu_credits++;
          LOGGER_DEBUG(
              logger, "Verifier: MT checksum {}",
              logging::memory_window_checksum(
                  pk->offload->memoryWindow(PkOffload::MT, PkOffload::Host)));
          LOGGER_DEBUG(
              logger,
              "Verifier: the MT roots generated in the GPU/copied to the CPU {}"
              " the version generated in the CPU",
              pk->offload->validMerkleRoots() ? "match" : "DO NOT match");

          pk->move_to(PkContext::VerifyingEddsa, profilers);
          cpu_workers.schedule_verify(*pk);
          LOGGER_TRACE(logger, "{} ComputingTree -> VerifyingEddsa",
                       pk->to_string());
        }
      }
      if (pk->state == PkContext::VerifyingEddsa) {
        if (pk->eddsa_verified) {
          if (pk->eddsa_valid) {
            pk->move_to(PkContext::Ready, profilers);
            LOGGER_TRACE(logger, "{} VerifyingEddsa -> Ready", pk->to_string());
          } else {
            pk->state = PkContext::Invalid;
            LOGGER_WARN(logger, "{} VerifyingEddsa -> Invalid",
                        pk->to_string());
          }
        }
      }
    }
  }

  std::map<ProcId, std::deque<std::unique_ptr<PkContext>>> free_pks;
  std::map<ProcId, std::deque<std::unique_ptr<PkContext>>> armed_pks;
  std::deque<std::unique_ptr<PkContext>> offloaded_pks;
  size_t gpu_credits = 4;

  PonyRcs &rcs;
  PkCpuWorkers cpu_workers;

  // Latency measurement
  PkContext::Profilers profilers;

  LOGGER_DECL(logger);
};

}  // namespace dory::pony

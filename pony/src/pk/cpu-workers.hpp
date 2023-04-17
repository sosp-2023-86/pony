#pragma once

#include <chrono>
#include <condition_variable>
#include <functional>
#include <map>
#include <thread>
#include <variant>

#include <dory/crypto/hash/blake3.hpp>
#include <dory/shared/match.hpp>
#include <dory/shared/pinning.hpp>

#include "../crypto.hpp"
#include "../mutex.hpp"
#include "../pinning.hpp"
#include "../util.hpp"
#include "cache.hpp"
#include "context.hpp"

namespace dory::pony {

class PkCpuWorkers {
  struct Stop {};
  using Work = std::reference_wrapper<PkContext>;
  using Todo = std::variant<Stop, Work>;

 public:
  PkCpuWorkers(EddsaCrypto& eddsa, size_t const nb_threads = 1) : eddsa{eddsa} {
    for (size_t i = 0; i < nb_threads; i++) {
      threads.emplace_back([&] {
        while (true) {
          auto todo = [&]() -> Todo {
            // std::unique_lock<Mutex> lock(mutex);
            // cond_var.wait(lock, [&] { return stop || !to_verify.empty(); });
            // if (!to_verify.empty()) {
            //   auto to_ret = to_verify.front();
            //   to_verify.pop_front();
            //   return to_ret;
            // }
            // return Stop{};
            while (true) {
              std::scoped_lock<Mutex> lock(mutex);
              while (!stop && to_verify.empty()) {
                mutex.unlock();
                busy_sleep(std::chrono::microseconds(1));
                mutex.lock();
              }
              if (!to_verify.empty()) {
                auto to_ret = to_verify.front();
                to_verify.pop_front();
                return to_ret;
              }
              return Stop{};
            }
          }();

          if (std::holds_alternative<Stop>(todo)) {
            return;
          }

          match{todo}(
              [&](Work& work) noexcept {
                auto& ctx = work.get();
                auto& pk = ctx.view;

                // 1. Verify the EdDSA signature
                auto& sig = pk.getSig();
                if (!already_verified(sig, ctx.signer)) {
                  if (!eddsa.verify(sig, ctx.signer)) {
                    ctx.eddsa_valid = false;
                    ctx.eddsa_verified = true;
                    return;
                  }
                  remember(sig, ctx.signer);
                }

                // 2. Verify that the pk hash is valid and included in the EdDSA
                bool const valid_pk_hash = [&]() {
                  if constexpr (Scheme == HORS &&
                                hors::PkEmbedding == hors::Merkle) {
                    return pk.getHash() ==
                           crypto::hash::blake3(pk.getMt().getRoots());
                  }
                  if constexpr (PresendEddsaOnly) {
                    return true;  // No need to verify.
                  }
                  return pk.getHash() == crypto::hash::blake3(pk.getHashes());
                }();
                ctx.eddsa_valid = valid_pk_hash && sig.includes(pk.getHash());
                ctx.eddsa_verified = true;
              },
              [](Stop& stop) noexcept { /* Should have returned. */ });
        }
      });
      auto const thread_name("pk-verifier");
      set_thread_name(threads.back(), thread_name);
      if (auto const core = get_core(thread_name)) {
        pin_thread_to_core(threads.back(), *core);
      }
    }
  }

  PkCpuWorkers(PkCpuWorkers const&) = delete;
  PkCpuWorkers& operator=(PkCpuWorkers const&) = delete;
  PkCpuWorkers(PkCpuWorkers&&) = delete;
  PkCpuWorkers& operator=(PkCpuWorkers&&) = delete;

  ~PkCpuWorkers() {
    stop = true;
    cond_var.notify_all();
    for (auto& thread : threads) {
      thread.join();
    }
  }

  void schedule_verify(PkContext& ctx) {
    std::scoped_lock<Mutex> lock(mutex);
    to_verify.emplace_back(ctx);
    cond_var.notify_one();
  }

 private:
  void remember(BatchedEddsaSignature const& sig, ProcId const signer) {
    std::scoped_lock<Mutex> lock(caches_mutex);
    auto& cache = caches.try_emplace(signer).first->second;
    cache.store(sig);
  }

  bool already_verified(BatchedEddsaSignature const& sig, ProcId const signer) {
    std::scoped_lock<Mutex> lock(caches_mutex);
    auto& cache = caches.try_emplace(signer).first->second;
    return cache.contains(sig);
  }

  EddsaCrypto& eddsa;
  std::vector<std::thread> threads;
  Mutex mutex;
  std::condition_variable_any cond_var;
  std::deque<std::reference_wrapper<PkContext>> to_verify;
  std::atomic<bool> stop = false;

  Mutex caches_mutex;
  std::map<ProcId, EddsaCache> caches;
};

}  // namespace dory::pony

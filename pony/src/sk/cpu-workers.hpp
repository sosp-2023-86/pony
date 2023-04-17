#pragma once

#include <array>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>
#include <variant>

#include <hipony/enumerate.hpp>

#include <dory/crypto/hash/blake3.hpp>
#include <dory/shared/match.hpp>
#include <dory/shared/pinning.hpp>

#include "../crypto.hpp"
#include "../mutex.hpp"
#include "../pinning.hpp"
#include "../util.hpp"
#include "context.hpp"

namespace dory::pony {

class SkCpuWorkers {
  struct Stop {};

  template <typename T>
  using OptionalRef = std::optional<std::reference_wrapper<T>>;

  using Work = std::array<OptionalRef<SkContext>, EddsaBatchSize>;
  using Todo = std::variant<Stop, Work>;

 public:
  SkCpuWorkers(EddsaCrypto& eddsa, size_t const nb_threads = 1) : eddsa{eddsa} {
    for (size_t i = 0; i < nb_threads; i++) {
      threads.emplace_back([&] {
        while (true) {
          auto todo = [&]() -> Todo {
            // std::unique_lock<Mutex> lock(mutex);
            // cond_var.wait(lock, [&] { return stop || !to_sign.empty(); });
            // if (!to_sign.empty()) {
            //   auto to_ret = to_sign.front();
            //   to_sign.pop_front();
            //   return to_ret;
            // }
            // return Stop{};
            while (true) {
              std::scoped_lock<Mutex> lock(mutex);
              while (!stop && to_sign.empty()) {
                mutex.unlock();
                busy_sleep(std::chrono::nanoseconds(100));
                mutex.lock();
              }

              // Given that signature verification is ~4x slower than signing,
              // it is important for the signer to force itself to batch so that
              // the verifier is not overwhelmed by EdDSA.
              // So, if we don't have 4 PKs to sign, we will wait a bit more.
              auto const start = std::chrono::steady_clock::now();
              while (to_sign.size() < 4 &&
                     std::chrono::steady_clock::now() - start <
                         std::chrono::microseconds(50)) {
                mutex.unlock();
                busy_sleep(std::chrono::nanoseconds(100));
                mutex.lock();
              }

              if (!to_sign.empty()) {
                Work to_ret;
                for (size_t i = 0; i < to_ret.size(); i++) {
                  if (!to_sign.empty()) {
                    to_ret[i] = to_sign.front();
                    to_sign.pop_front();
                  } else {
                    to_ret[i] = std::nullopt;
                  }
                }
                return to_ret;
              }
              return Stop{};
            }
          }();

          if (std::holds_alternative<Stop>(todo)) {
            return;
          }

          match{todo}(
              [&eddsa](Work const& work) noexcept {
                // 1. Compute the hash of the roots of every context.
                std::array<Hash, EddsaBatchSize> hashes;
                for (auto const& [i, opt_sk] : hipony::enumerate(work)) {
                  if (opt_sk) {
                    auto& sk = opt_sk->get();
                    if constexpr (Scheme == HORS &&
                                  hors::PkEmbedding == hors::Merkle) {
                      auto const& roots = sk.view.getPk().getMt().getRoots();
                      hashes[i] = crypto::hash::blake3(roots);
                    } else {
                      auto const& pk_hashes = sk.view.getPk().getHashes();
                      hashes[i] = crypto::hash::blake3(pk_hashes);
                    }
                    sk.view.getPkHash() = hashes[i];
                  } else {
                    hashes[i] = {};  // We zero the hash.
                  }
                }

                // 2. Sign the hashes (padded with 0s).
                auto const* const to_sign =
                    reinterpret_cast<uint8_t const*>(&hashes);
                auto const sig = eddsa.sign(to_sign, sizeof(hashes));

                // 2.5 Compute nonces for each context.
                for (auto const& opt_sk : work) {
                  if (opt_sk) {
                    auto hasher = crypto::hash::blake3_init();
                    crypto::hash::blake3_update(
                        hasher, opt_sk->get().offload->getSeed());
                    crypto::hash::blake3_final_there(
                        hasher, opt_sk->get().nonces[0].data(),
                        sizeof(opt_sk->get().nonces));
                  }
                }

                // 3. Write the hashes and signatures to every context.
                for (auto const& opt_sk : work) {
                  if (opt_sk) {
                    auto& sk_sig = opt_sk->get().view.getPkSig();
                    sk_sig.hashes = hashes;
                    sk_sig.sig = sig;
                    opt_sk->get().eddsa_computed = true;
                  }
                }
              },
              [](Stop& stop) noexcept { /* Should have returned. */ });
        }
      });
      auto const thread_name("pk-signer");
      set_thread_name(threads.back(), thread_name);
      if (auto const core = get_core(thread_name)) {
        pin_thread_to_core(threads.back(), *core);
      }
    }
  }

  SkCpuWorkers(SkCpuWorkers const&) = delete;
  SkCpuWorkers& operator=(SkCpuWorkers const&) = delete;
  SkCpuWorkers(SkCpuWorkers&&) = delete;
  SkCpuWorkers& operator=(SkCpuWorkers&&) = delete;

  ~SkCpuWorkers() {
    stop = true;
    cond_var.notify_all();
    for (auto& thread : threads) {
      thread.join();
    }
  }

  void schedule_sign(SkContext& ctx) {
    std::scoped_lock<Mutex> lock(mutex);
    to_sign.emplace_back(ctx);
    cond_var.notify_one();
  }

 private:
  EddsaCrypto& eddsa;
  std::vector<std::thread> threads;
  Mutex mutex;
  std::condition_variable_any cond_var;
  std::deque<std::reference_wrapper<SkContext>> to_sign;
  std::atomic<bool> stop = false;
};

}  // namespace dory::pony

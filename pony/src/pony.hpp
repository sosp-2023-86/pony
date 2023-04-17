#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>

#include <dory/conn/ud.hpp>
#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>
#include <dory/memory/pool/pool-allocator.hpp>
#include <dory/shared/dynamic-bitset.hpp>
#include <dory/shared/logger.hpp>

#include "cache.hpp"
#include "mutex.hpp"
#include "parser.hpp"
#include "pk/pipeline.hpp"
#include "rc.hpp"
#include "sk/pipeline.hpp"
#include "types.hpp"

namespace dory::pony {

class PonyInit {
  LOGGER_DECL(logger);

  ctrl::OpenDevice open_device;
  ctrl::ResolvedPort resolved_port;
  ctrl::ControlBlock control_block;

 public:
  PonyInit(std::string const &dev_name);

 private:
  ctrl::OpenDevice get_device(std::string const &dev_name);
  ctrl::ControlBlock build_block(std::string const &dev_name,
                                 ctrl::OpenDevice open_dev,
                                 ctrl::ResolvedPort reslv_port);

 public:
  ctrl::ControlBlock *operator->() { return &control_block; }
  ctrl::ControlBlock &operator*() { return control_block; }
};

class Pony {
 public:
  Pony(ProcId id, bool caching = true);
  ~Pony();

  // As Pony manages a thread, it should not be moved.
  Pony(Pony const &) = delete;
  Pony &operator=(Pony const &) = delete;
  Pony(Pony &&) = delete;
  Pony &operator=(Pony &&) = delete;

  void sign(Signature &sig, uint8_t const *m, size_t mlen);
  bool verify(Signature const &sig, uint8_t const *m, size_t mlen, ProcId pid);
  std::optional<bool> try_fast_verify(Signature const &sig, uint8_t const *m,
                                      size_t mlen, ProcId pid);

  bool slow_verify(HorsMerkleSignature const &sig, uint8_t const *m,
                   size_t mlen, ProcId pid);

  bool slow_verify(HorsFullSignature const &sig, uint8_t const *m, size_t mlen,
                   ProcId pid);

  bool slow_verify(HorsSyncSignature const &sig, uint8_t const *m, size_t mlen,
                   ProcId pid);

  bool slow_verify(WotsSignature const &sig, uint8_t const *m, size_t mlen,
                   ProcId pid);

  void enable_slow_path(bool const enable) { slow_path = enable; }

  bool replenished_sks(size_t replenished = SkCtxs);

  bool replenished_pks(ProcId const pid, size_t replenished = SkCtxs);

  void report_latencies() {
    sk_pipeline.report_latencies();
    pk_pipeline.report_latencies();
  }

 private:
  RuntimeConfig config;
  EddsaCrypto eddsa;
  PonyInit cb;
  PonyRcs rcs;

  // Scheduling thread logic
  void scheduling_loop();

  PkPipeline pk_pipeline;
  void fetch_ready_pks();

  SkPipeline sk_pipeline;
  void fetch_ready_sks();

  // Scheduling thread control
  std::thread scheduler;
  void stop_scheduler() {
    stop = true;
    scheduler.join();
  }
  std::atomic<bool> stop = false;

  // Keys exposed to the application threads via sign/verify
  std::map<ProcId, std::deque<std::unique_ptr<PkContext>>> public_keys;
  Mutex pk_mutex;
  std::deque<std::unique_ptr<SkContext>> secret_keys;
  Mutex sk_mutex;
  std::condition_variable_any sk_cond_var;

  bool slow_path = false;

  bool caching;
  std::vector<SignatureCache> sig_cache;

  LOGGER_DECL(logger);
};
}  // namespace dory::pony

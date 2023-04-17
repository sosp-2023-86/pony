#include <algorithm>
#include <chrono>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include <fmt/core.h>

#include <dory/conn/ud.hpp>
#include <dory/crypto/hash/blake3.hpp>
#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>
#include <dory/shared/pinning.hpp>

#include "hors.hpp"
#include "mutex.hpp"
#include "pinning.hpp"
#include "pony.hpp"
#include "sanity/check.hpp"
#include "util.hpp"

namespace dory::pony {

PonyInit::PonyInit(std::string const &dev_name)
    : LOGGER_INIT(logger, "Pony"),
      open_device{get_device(dev_name)},
      resolved_port{open_device},
      control_block{build_block(dev_name, open_device, resolved_port)} {
  LOGGER_WARN(logger, "!!!THE SIG. CACHE IS NOT IMPLEMENTED!!!");
  if (Scheme == HORS) {
    LOGGER_INFO(logger,
                "Scheme: HORS, Key size: {}KiB, Sig size: {}B, Sig type: {}, "
                "secrets/sig: {}, "
                "sigs/SK: {}, sec."
                " level: {}bits, SK ctxs: {}",
                sizeof(PublicKey) / 1024, sizeof(Signature), hors::PkEmbedding,
                SecretsPerSignature, SignaturesPerSecretKey, "?? ", SkCtxs);
  } else {
    LOGGER_INFO(
        logger,
        "Scheme: WOTS, Key size: {}KiB, Sig size: {}B, secrets/sig: {}, "
        "sec. level: {}bits, SK ctxs: {}, Sig verification: {}",
        sizeof(PublicKey) / 1024, sizeof(Signature), SecretsPerSignature, "?? ",
        SkCtxs, wots::VerifyOnGpu ? "GPU" : "CPU");
  }
}

ctrl::OpenDevice PonyInit::get_device(std::string const &dev_name) {
  bool device_found = false;

  ctrl::Devices d;
  ctrl::OpenDevice open_dev;
  for (auto &dev : d.list()) {
    if (dev_name == std::string(dev.name())) {
      open_dev = std::move(dev);
      device_found = true;
      break;
    }
  }

  if (!device_found) {
    LOGGER_ERROR(logger,
                 "Could not find the RDMA device {}. Run `ibv_devices` to get "
                 "the device names.",
                 dev_name);
    std::abort();
  }

  LOGGER_INFO(logger, "Device: {} / {}, {}, {}", open_dev.name(),
              open_dev.devName(),
              ctrl::OpenDevice::typeStr(open_dev.nodeType()),
              ctrl::OpenDevice::typeStr(open_dev.transportType()));

  return open_dev;
}

ctrl::ControlBlock PonyInit::build_block(std::string const &dev_name,
                                         ctrl::OpenDevice open_dev,
                                         ctrl::ResolvedPort reslv_port) {
  size_t binding_port = 0;
  LOGGER_INFO(logger, "Binding to port {} of opened device {}", binding_port,
              open_dev.name());

  auto binded = reslv_port.bindTo(binding_port);

  if (!binded) {
    LOGGER_ERROR(logger, "Could not bind the RDMA device {}", dev_name);
    std::abort();
  }

  LOGGER_INFO(logger, "Binded successfully (port_id, port_lid) = ({}, {})",
              +resolved_port.portId(), +resolved_port.portLid());

  LOGGER_INFO(logger, "Configuring the control block");
  return ctrl::ControlBlock(reslv_port);
}

Pony::Pony(ProcId id, bool caching)
    : config(id),
      eddsa(config.myId(), config.allIds()),
      cb{config.deviceName()},
      rcs{*cb, config.myId(), config.remoteIds()},
      pk_pipeline{rcs, eddsa, *rcs.host_alloc, *rcs.gpu_alloc},
      sk_pipeline{rcs, eddsa, *rcs.host_alloc, *rcs.gpu_alloc},
      caching{caching},
      LOGGER_INIT(logger, "Pony") {
  // Check that the macro config matches the compilation config
  sanity::check();

  // Create a list of verified pks for each id
  for (auto const id : config.remoteIds()) {
    public_keys.try_emplace(id);
  }

  size_t elems = static_cast<size_t>(*std::max_element(config.allIds().begin(),
                                                       config.allIds().end())) +
                 1;
  LOGGER_DEBUG(
      logger, "Creating a signature cache for processes up to index {}", elems);

  sig_cache.reserve(elems);
  if (caching) {
    sig_cache.resize(elems);
  } else {
    for (size_t i = 0; i < elems; i++) {
      sig_cache.emplace_back(true);
    }
  }

  scheduler = std::thread([this]() { this->scheduling_loop(); });
  auto const thread_name("bg");
  set_thread_name(scheduler, thread_name);
  if (auto const core = get_core(thread_name)) {
    pin_thread_to_core(scheduler, *core);
  }
}

Pony::~Pony() { stop_scheduler(); }

void Pony::sign(Signature &sig, uint8_t const *const m, size_t const mlen) {
  std::unique_lock<Mutex> lock(sk_mutex);
  LOGGER_TRACE(logger, "{} SKs available.", secret_keys.size());
  // sk_cond_var.wait(lock, [this]() { return !secret_keys.empty(); });
  while (secret_keys.empty()) {
    sk_mutex.unlock();
    busy_sleep(std::chrono::nanoseconds(100));
    sk_mutex.lock();
  }
  // By construction, the first key is not worn out, so we can use it.
  auto &sk = secret_keys.front();

  sig = sk->view.sign(sk->nonces[sk->signatures++], m, mlen,
                      sig_cache.at(config.myId()));
  LOGGER_TRACE(logger, "SK used {} times.", sk->signatures);
  if (sk->worn_out()) {
    sk_pipeline.recycle(std::move(sk));
    secret_keys.pop_front();
    LOGGER_DEBUG(logger, "SK exhausted.");
  }
}

bool Pony::verify(Signature const &sig, uint8_t const *const m,
                  size_t const mlen, ProcId const pid) {
  while (true) {
    auto const fast_verif = try_fast_verify(sig, m, mlen, pid);
    if (fast_verif) {
      return *fast_verif;
    }
    if (slow_path) {
      LOGGER_WARN(logger, "No PK available for {}: slow verification.", pid);
      return slow_verify(sig, m, mlen, pid);
    }
    // We repeat until we can verify.
    // TODO: spin a bit to improve the latency percentiles as it helps
    // rebuilding the PK cache.
  }
}

std::optional<bool> Pony::try_fast_verify(Signature const &sig,
                                          uint8_t const *const m,
                                          size_t const mlen, ProcId const pid) {
  // Try to find a matching PK to fast verify the signature.
  if (pid != config.myId()) {
    std::scoped_lock<Mutex> lock(pk_mutex);
    LOGGER_TRACE(logger, "{} PKs available for process {}.",
                 public_keys[pid].size(), pid);
    for (auto const &pk : public_keys[pid]) {
      if (pk->view.associatedTo(sig)) {
        if (pk->view.verify(sig, m, mlen, sig_cache.at(pid),
                            pk->offload.get())) {
          pk->verifications++;
          return true;
        }
        return false;
      }
    }
  } else {
    // We are gonna try to find the SK we used.
    std::scoped_lock<Mutex> lock(sk_mutex);
    for (auto const &sk : secret_keys) {
      if (sk->view.associatedTo(sig)) {
        auto const &pk = sk->view.getPk();
        if (pk.verify(sig, m, mlen, sig_cache.at(config.myId()), nullptr)) {
          return true;
        }
        LOGGER_WARN(logger, "Local signature failed verification.");
        return false;
      }
    }
  }
  // The public key is not available, thus we abort the verification.
  return std::nullopt;
}

bool Pony::slow_verify(HorsMerkleSignature const &sig, uint8_t const *const m,
                       size_t const mlen, ProcId const pid) {
  // 1. Verify the pk signature.
  if (sig.pk_hash != crypto::hash::blake3(sig.roots)) {
    LOGGER_WARN(logger, "Pk hash does not match the roots.", pid);
    return false;
  }

  if (!sig.pk_sig.includes(sig.pk_hash)) {
    LOGGER_WARN(logger, "Pk hash not included in the batched EdDSA.", pid);
    return false;
  }

  if (!eddsa.verify(sig.pk_sig, pid)) {
    LOGGER_WARN(logger, "Invalid EdDSA batched sig.");
    return false;
  }

  // 2. Verify HORS secrets (i.e., that the right secrets were revealed).
  HorsHash const h(sig.pk_hash, sig.nonce, m, m + mlen);
  for (size_t hash_offset = 0, i = 0; i < SecretsPerSignature;
       i++, hash_offset += hors::LogSecretsPerSecretKey) {
    auto const secret_index = h.getSecretIndex(hash_offset);
    auto const &[secret, proof] = sig.secrets[i];

    auto const leaf = crypto::hash::blake3(secret);

    auto directions = secret_index;
    auto acc = leaf;
    for (size_t i = 0; i < proof.path.size(); i++) {
      auto direction = directions & 1;
      directions >>= 1;
      auto hs = crypto::hash::blake3_init();
      if (direction == 0) {
        crypto::hash::blake3_update(hs, acc);
        crypto::hash::blake3_update(hs, proof.path[proof.path.size() - 1 - i]);
      } else {
        crypto::hash::blake3_update(hs, proof.path[proof.path.size() - 1 - i]);
        crypto::hash::blake3_update(hs, acc);
      }
      acc = crypto::hash::blake3_final(hs);
    }

    if (acc != sig.roots[secret_index >> proof.path.size()]) {
      LOGGER_WARN(logger, "Invalid merkle proof.");
      return false;
    }
  }

  return true;
}

bool Pony::slow_verify(HorsFullSignature const &sig, uint8_t const *const m,
                       size_t const mlen, ProcId const pid) {
  // 1. Verify the EdDSA signature.
  if (!sig.pk_sig.includes(sig.pk_hash)) {
    LOGGER_WARN(logger, "PK hash not included in the batched EdDSA.", pid);
    return false;
  }

  if (!eddsa.verify(sig.pk_sig, pid)) {
    LOGGER_WARN(logger, "Invalid EdDSA batched sig.");
    return false;
  }

  // 2. Verify HORS secrets (i.e., that the right secrets were revealed).
  auto sig_hashes = sig.secrets_and_hashes;
  HorsHash const h(sig.pk_hash, sig.nonce, m, m + mlen);
  for (size_t hash_offset = 0, i = 0; i < SecretsPerSignature;
       i++, hash_offset += hors::LogSecretsPerSecretKey) {
    auto const secret_index = h.getSecretIndex(hash_offset);
    sig_hashes[secret_index] =
        crypto::hash::blake3(sig.secrets_and_hashes[secret_index]);
  }

  return crypto::hash::blake3(sig_hashes) == sig.pk_hash;
}

bool Pony::slow_verify(HorsSyncSignature const &sig, uint8_t const *const m,
                       size_t const mlen, ProcId const pid) {
  throw std::runtime_error("Sync signatures cannot be verified without a PK.");
}

bool Pony::slow_verify(WotsSignature const &sig, uint8_t const *const m,
                       size_t const mlen, ProcId const pid) {
  // 1. Verify the EdDSA signature.
  if (!sig.pk_sig.includes(sig.pk_hash)) {
    LOGGER_WARN(logger, "PK hash not included in the batched EdDSA.", pid);
    return false;
  }

  if (!eddsa.verify(sig.pk_sig, pid)) {
    LOGGER_WARN(logger, "Invalid EdDSA batched sig.");
    return false;
  }

  // 2. Verify WOST secrets (i.e., that the right secrets were revealed).
  auto sig_hashes = sig.secrets;

  WotsHash h(sig.pk_hash, sig.nonce, m, m + mlen);

  for (size_t secret = 0; secret < SecretsPerSignature; secret++) {
    auto const depth = h.getSecretDepth(secret);
    auto const to_hash = SecretsDepth - depth - 1;
    for (size_t i = 0; i < to_hash; i++) {
      sig_hashes[secret] = crypto::hash::blake3(sig_hashes[secret]);
    }
  }

  return crypto::hash::blake3(sig_hashes) == sig.pk_hash;
}

void Pony::scheduling_loop() {
  while (!stop) {
    pk_pipeline.tick();
    fetch_ready_pks();
    sk_pipeline.tick();
    fetch_ready_sks();
  }
}

void Pony::fetch_ready_pks() {
  while (auto pk = pk_pipeline.extract_ready()) {
    std::scoped_lock<Mutex> lock(pk_mutex);
    auto &keys = public_keys[pk->signer];
    if (keys.size() == BufferedPksPerProcess) {
      pk_pipeline.recycle(std::move(keys.front()));
      keys.pop_front();
    }
    keys.emplace_back(std::move(pk));
    LOGGER_DEBUG(logger, "{} exposed", keys.back()->to_string());
  }
}

void Pony::fetch_ready_sks() {
  // Move the sks that are ready (they should mostly get ready in order).
  while (auto sk = sk_pipeline.extract_ready()) {
    std::scoped_lock<Mutex> lock(sk_mutex);
    secret_keys.emplace_back(std::move(sk));
    sk_cond_var.notify_all();
    LOGGER_DEBUG(logger, "{} exposed", secret_keys.back()->to_string());
  }
}

bool Pony::replenished_sks(size_t const replenished) {
  std::scoped_lock<Mutex> lock(sk_mutex);
  return secret_keys.size() >= replenished;
}

bool Pony::replenished_pks(ProcId const pid, size_t const replenished) {
  std::scoped_lock<Mutex> lock(pk_mutex);
  size_t virgin_pks = 0;
  for (auto const &pk : public_keys[pid]) {
    if (pk->verifications == 0) {
      virgin_pks++;
    }
  }
  return virgin_pks >= replenished;
}

}  // namespace dory::pony

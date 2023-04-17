#pragma once

#include <algorithm>
#include <exception>
#include <vector>

#include <dory/conn/rc-exchanger.hpp>
#include <dory/conn/rc.hpp>
#include <dory/conn/ud.hpp>
#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>
#include <dory/memory/pool/pool-allocator.hpp>
#include <dory/shared/logger.hpp>

#include <fmt/core.h>
#include <fmt/ranges.h>

#include "alloc.hpp"
#include "config.hpp"
#include "pk/context.hpp"
#include "sk/context.hpp"
#include "types.hpp"
#include "util.hpp"

namespace dory::pony {

class PonyRcs {
 public:
  PonyRcs(ctrl::ControlBlock &cb, ProcId my_id,
          std::vector<ProcId> const &remote_ids)
      : LOGGER_INIT(logger, "Pony::RCs"),
        remote_ids{remote_ids},
        store{nspace},
        host_alloc{build_host_alloc(AllocatedSize)},
        gpu_alloc{build_gpu_alloc(AllocatedSize)},
        ce{build_ce(my_id, remote_ids, cb)} {
    auto const hw_credits =
        std::min(static_cast<size_t>(dory::ctrl::ControlBlock::CqDepth /
                                     remote_ids.size()),
                 static_cast<size_t>(dory::conn::ReliableConnection::WrDepth));
    for (auto &id : remote_ids) {
      connections.emplace_back(id, ce.extract(id));
      send_credits.try_emplace(id, hw_credits);
      recv_credits.try_emplace(id, hw_credits);
    }
  }

  bool try_arm_recv(PkContext &ctx) {
    if (recv_credits[ctx.signer] == 0) {
      return false;
    }

    auto &rc =
        std::find_if(connections.begin(), connections.end(), [&](auto &kv) {
          return kv.first == ctx.signer;
        })->second;

    auto const pk_start =
        ctx.offload->memoryWindow(PkOffload::PK, PkOffload::Host).p;
    auto const pk_size = SentPkPrefix;

    LOGGER_TRACE(logger,
                 "Arming to receiving PK (length {} bytes) at address {}",
                 pk_size, pk_start);

    void *arr[1];
    arr[0] = pk_start;
    auto const posted =
        rc.postRecvMany(reinterpret_cast<uint64_t>(&ctx), arr, 1, pk_size);
    if (!posted) {
      throw std::runtime_error(
          fmt::format("Error while arming for {}", ctx.signer));
    }

    LOGGER_TRACE(logger, "{} RECV armed", ctx.to_string());
    recv_credits[ctx.signer]--;
    return true;
  }

  PkContext *try_poll_recv() {
    for (size_t i = 0; i < connections.size(); i++) {
      size_t idx = recv_poll_starting_index++ % connections.size();
      auto &[_, rc] = connections[idx];

      wce.resize(1);

      if (!rc.pollCqIsOk(conn::ReliableConnection::Cq::RecvCq, wce)) {
        throw std::runtime_error("Polling error.");
      }

      if (!wce.empty()) {
        auto &wc = wce[0];

        if (wc.status != IBV_WC_SUCCESS) {
          throw std::runtime_error(fmt::format(
              "Pony RCs try_poll_recv. WC not successful ({}).", wc.status));
        }

        auto *const ctx = reinterpret_cast<PkContext *>(wc.wr_id);
        recv_credits[ctx->signer]++;

        LOGGER_TRACE(logger, "{} RECVed", ctx->to_string());
        return ctx;
      }
    }

    return nullptr;
  }

  void poll_send() {
    for (auto &[id, rc] : connections) {
      wce.resize(1);

      if (!rc.pollCqIsOk(conn::ReliableConnection::Cq::SendCq, wce)) {
        throw std::runtime_error("Polling error.");
      }

      if (!wce.empty()) {
        auto &wc = wce[0];

        if (wc.status != IBV_WC_SUCCESS) {
          throw std::runtime_error(fmt::format(
              "Pony RCs poll_send. WC not successful ({}).", wc.status));
        }

        auto const [unpacked_id, ctx] = unpack(wc.wr_id);
        send_credits[unpacked_id]++;
        ctx->acks++;

        LOGGER_TRACE(logger, "{} SEND acked by {}: {}/{}.", ctx->to_string(),
                     unpacked_id, ctx->acks, ctx->max_acks);
      }
    }
  }

  bool try_send(SkContext &ctx) {
    // We only send if everyone has credits.
    // This synchrony assumption simplifies the implementation without
    // impacting the performance.
    for (auto &[id, _] : connections) {
      if (send_credits[id] == 0) {
        return false;
      }
    }
    // We know we can send to everyone.
    for (auto &[id, rc] : connections) {
      // Useless check as long as we have the synchrony assumption above.
      if (send_credits[id] > 0) {
        send_credits[id]--;
        auto const pk_addr =
            ctx.offload->memoryWindow(SkOffload::PK, SkOffload::Host).p;
        auto const pk_size = SentPkPrefix;
        LOGGER_DEBUG(logger, "Sending PK. Length {} bytes, {}", pk_size,
                     logging::public_key(pk_addr));
        auto const posted =
            rc.postSendSingleSend(pack(id, &ctx), pk_addr, pk_size);
        if (!posted) {
          throw std::runtime_error(
              fmt::format("Error while sending to {}", id));
        } else {
          LOGGER_TRACE(logger, "{} SENT to {}, remaining credits: {}",
                       ctx.to_string(), id, send_credits[id]);
        }
        // Dead code as long as we have the synchrony assumption above.
      } else {
        ctx.acks++;
        LOGGER_TRACE(logger, "{} NOT SENT to {} (no credits): {}/{}",
                     ctx.to_string(), id, ctx.acks, ctx.max_acks);
      }
    }
    return true;
  }

  uint64_t pack(ProcId id, SkContext const *ctx) {
    auto ptr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ctx));
    // fmt::print("I packed ptr {} and id {}\n", ptr, id);
    return (static_cast<uint64_t>(id) << 48) | ptr;
  }

  std::pair<ProcId, SkContext *> unpack(uint64_t const wr_id) {
    auto const id = static_cast<ProcId>(wr_id >> 48);
    auto const ptr = reinterpret_cast<SkContext *>((wr_id << 16) >> 16);
    // fmt::print("I unpacked ptr {} and id {} from {}\n",
    // reinterpret_cast<uintptr_t>(ptr), id, wr_id);
    return {id, ptr};
  }

 private:
  std::unique_ptr<cuda::HostAllocator> build_host_alloc(size_t alloc_size) {
    if (cuda::have_gpu()) {
      return std::make_unique<cuda::HostCudaAllocator>(alloc_size);
    } else {
      LOGGER_WARN(logger,
                  "Did not detect an NVIDIA GPU. Switching to CPU mock for "
                  "HOST memory");
      return std::make_unique<cuda::HostNormalAllocator>(alloc_size);
    }
  }

  std::unique_ptr<cuda::DeviceAllocator> build_gpu_alloc(size_t alloc_size) {
    if (cuda::have_gpu()) {
      return std::make_unique<cuda::GpuCudaAllocator>(alloc_size);
    } else {
      LOGGER_WARN(logger,
                  "Did not detect an NVIDIA GPU. Switching to CPU mock for "
                  "DEVICE memory");
      return std::make_unique<cuda::GpuNormalAllocator>(alloc_size);
    }
  }

  conn::RcConnectionExchanger<ProcId> build_ce(
      ProcId my_id, std::vector<ProcId> const &remote_ids,
      ctrl::ControlBlock &cb) {
    cb.registerPd(namespaced("primary"));
    cb.allocateBufferFromPtr(namespaced("host-buf"), host_alloc->start(),
                             host_alloc->size());
    cb.registerMr(
        namespaced("shared-mr"), namespaced("primary"), namespaced("host-buf"),
        ctrl::ControlBlock::LOCAL_READ | ctrl::ControlBlock::LOCAL_WRITE |
            ctrl::ControlBlock::REMOTE_READ | ctrl::ControlBlock::REMOTE_WRITE);

    conn::RcConnectionExchanger<ProcId> ce_(my_id, remote_ids, cb);

    cb.registerCq(namespaced("send-cq"));
    cb.registerCq(namespaced("recv-cq"));

    ce_.configureAll(namespaced("primary"), namespaced("shared-mr"),
                     namespaced("send-cq"), namespaced("recv-cq"));
    ce_.announceAll(store, namespaced("announced-qps"));
    ce_.announceReady(store, namespaced("announced-qps"),
                      namespaced("announced-qps-ready"));
    ce_.waitReadyAll(store, namespaced("announced-qps"),
                     namespaced("announced-qps-ready"));

    ce_.connectAll(
        store, namespaced("announced-qps"),
        ctrl::ControlBlock::LOCAL_READ | ctrl::ControlBlock::LOCAL_WRITE |
            ctrl::ControlBlock::REMOTE_READ | ctrl::ControlBlock::REMOTE_WRITE);

    return ce_;
  }

  std::string namespaced(std::string const &name) {
    return fmt::format("{}rcs-{}", nspace, name);
  }

  LOGGER_DECL(logger);

 public:
  std::vector<ProcId> remote_ids;

  size_t recv_arm_starting_index = 0;
  size_t recv_poll_starting_index = 0;

  memstore::MemoryStore store;

  std::unique_ptr<cuda::HostAllocator> host_alloc;
  std::unique_ptr<cuda::DeviceAllocator> gpu_alloc;

  conn::RcConnectionExchanger<ProcId> ce;
  std::vector<std::pair<ProcId, conn::ReliableConnection>> connections;

  std::map<ProcId, size_t> send_credits;
  std::map<ProcId, size_t> recv_credits;

  std::vector<struct ibv_wc> wce;
};
}  // namespace dory::pony

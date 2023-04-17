#include <memory>
#include <vector>

#include <dory/conn/ud.hpp>
#include <dory/ctrl/block.hpp>
#include <dory/memory/pool/pool-allocator.hpp>
#include <dory/shared/logger.hpp>

#include "config.hpp"
#include "rc.hpp"
#include "types.hpp"

namespace dory::pony {

class PonyQpInit {
 private:
  using ReceivedPublicKey = conn::UdReceiveSlot<PublicKey>;

 public:
  PonyQpInit(ctrl::ControlBlock &cb, std::string const &mc_group_name);

  std::shared_ptr<conn::UnreliableDatagram> build_ud(ctrl::ControlBlock &cb);

  PublicKey *send_slot() { return send_pool->create(); }

  void return_send_slot(PublicKey *ptr) { send_pool->destroy(ptr); }

  void poll_send_slots(size_t to_poll = 1) {
    while (to_poll) {
      wce_send.resize(to_poll);
      if (!ud->pollCqIsOk<conn::UnreliableDatagram::SendCQ>(wce_send)) {
        throw std::runtime_error("Polling error.");
      }
      if (!wce_send.empty()) {
        std::cout << "Send polled " << wce_send.size() << std::endl;
      }
      for (auto &wc : wce_send) {
        if (wc.status != IBV_WC_SUCCESS) {
          throw std::runtime_error(
              fmt::format("WC not successful ({})", wc.status));
        }
      }
      to_poll -= wce_send.size();
    }
  }

  void arm_receive_slots() {
    while (auto *addr = recv_pool->create()) {
      fmt::print("Size of post-recv {}\n",
                 sizeof(ReceivedPublicKey::inner_type));
      ud->postRecv(req_id, reinterpret_cast<void *>(addr),
                   sizeof(ReceivedPublicKey::inner_type));
      req_id += 1;
    }
  }

  void poll_receive_slots(size_t to_poll = 1) {
    while (to_poll) {
      wce_recv.resize(to_poll);
      if (!ud->pollCqIsOk<conn::UnreliableDatagram::RecvCQ>(wce_recv)) {
        throw std::runtime_error("Polling error.");
      }
      if (!wce_recv.empty()) {
        std::cout << "Recv polled " << wce_recv.size() << std::endl;
      }
      for (auto &wc : wce_recv) {
        if (wc.status != IBV_WC_SUCCESS) {
          throw std::runtime_error("WC not successful.");
        }
      }
      to_poll -= wce_recv.size();
    }
  }

 private:
  std::string namespaced(std::string const &name);
  uint64_t req_id = 0;

  LOGGER_DECL(logger);

 public:
  std::shared_ptr<conn::UnreliableDatagram> ud;
  conn::McGroup mc_group;
  ctrl::ControlBlock::MemoryRegion mr;

  memory::pool::ArenaPoolAllocator overlay;
  std::unique_ptr<memory::pool::PoolAllocator<PublicKey>> send_pool;
  std::unique_ptr<memory::pool::PoolAllocator<ReceivedPublicKey>> recv_pool;

  std::vector<struct ibv_wc> wce_send;
  std::vector<struct ibv_wc> wce_recv;
};

}  // namespace dory::pony

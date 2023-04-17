#include "ud-init.hpp"

namespace dory::pony {

PonyQpInit::PonyQpInit(ctrl::ControlBlock &cb, std::string const &mc_group_name)
    : LOGGER_INIT(logger, "Pony"),
      ud{build_ud(cb)},
      mc_group{cb, namespaced("primary"), ud, mc_group_name},
      mr{cb.mr(namespaced("shared-mr"))},
      overlay{reinterpret_cast<void *>(mr.addr), allocated_size, nullptr} {
  send_pool = overlay.createPool<PublicKey>(pool_size, alignment);
  recv_pool = overlay.createPool<ReceivedPublicKey>(pool_size, alignment);
}

std::shared_ptr<conn::UnreliableDatagram> PonyQpInit::build_ud(
    ctrl::ControlBlock &cb) {
  cb.registerPd(namespaced("primary"));
  cb.allocateBuffer(namespaced("shared-buf"), allocated_size, alignment);
  cb.registerMr(
      namespaced("shared-mr"), namespaced("primary"), namespaced("shared-buf"),
      ctrl::ControlBlock::LOCAL_READ | ctrl::ControlBlock::LOCAL_WRITE |
          ctrl::ControlBlock::REMOTE_READ | ctrl::ControlBlock::REMOTE_WRITE);
  cb.registerCq(namespaced("send-cq"));
  cb.registerCq(namespaced("recv-cq"));

  auto ud = std::make_shared<conn::UnreliableDatagram>(
      cb, namespaced("primary"), namespaced("shared-mr"), namespaced("send-cq"),
      namespaced("send-cq"));

  LOGGER_DEBUG(logger, "My UD QP is serialized as {}", ud->info().serialize());
  return ud;
}

std::string PonyQpInit::namespaced(std::string const &name) {
  return fmt::format("{}{}", nspace, name);
}

}  // namespace dory::pony

#pragma once

#include "alloc.hpp"
#include "pk/offload.hpp"
#include "types.hpp"

namespace dory::pony {
class CudaVerifier : public PkOffload {
 public:
  CudaVerifier(cuda::HostAllocator &host_alloc,
               cuda::DeviceAllocator &gpu_alloc);

  void reset() override;
  void scheduleCompute() override;

  bool validMerkleRoots() override;

  bool ready() override;

  bool verify(WotsSignature const &sig, uint8_t const *msg,
              size_t const msg_len) override;

  MemoryWindow memoryWindow(MemoryWindowKind kind,
                            MemoryWindowDevice device) override;

 private:
  struct pimpl;
  struct pimpl_deleter {
    void operator()(pimpl *) const;
  };
  std::unique_ptr<pimpl, pimpl_deleter> impl;
};
}  // namespace dory::pony

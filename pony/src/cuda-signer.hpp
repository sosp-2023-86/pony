#pragma once

#include "alloc.hpp"
#include "sk/offload.hpp"
#include "types.hpp"

namespace dory::pony {
class CudaSigner : public SkOffload {
 public:
  CudaSigner(Seed const &seed, cuda::HostAllocator &host_alloc,
             cuda::DeviceAllocator &gpu_alloc);

  void reset(Seed const &s) override;
  Seed const &getSeed() const override;
  void scheduleCompute() override;

  bool validSecretKey() override;
  bool validPublicKey() override;
  bool validMerkleRoots() override;

  bool ready() override;

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

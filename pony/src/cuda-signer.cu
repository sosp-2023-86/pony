#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>

#include "cuda-signer.hpp"
#include "cuda/core.cuh"

#define ARRAY_TYPE_SZ(x) \
  sizeof(std::remove_reference_t<decltype(x)>::value_type)

namespace dory::pony {

class CudaSigner::pimpl : private cuda::SignerVerifierBase {
 public:
  pimpl(cuda::Seed const& seed, cuda::HostAllocator& host_alloc,
        cuda::DeviceAllocator& gpu_alloc)
      : sk{seed, host_alloc, gpu_alloc},
        pk{&sk, host_alloc, gpu_alloc},
        mt{&pk, host_alloc, gpu_alloc} {}

  void reset(cuda::Seed const& s) {
    sk.resetSeed(s);
    cuda_ctx.resetStopEvent();
  }

  Seed const& getSeed() const { return sk.getSeed(); }

  void scheduleCompute() {
    sk.schedulePopulate(cuda_ctx.compute_stream);
    sk.scheduleCopyBack(cuda_ctx.compute_stream);
    pk.schedulePopulate(cuda_ctx.compute_stream);
    pk.scheduleCopyBack(cuda_ctx.compute_stream);
    if constexpr (Scheme == HORS && hors::PkEmbedding == hors::Merkle) {
      mt.schedulePopulate(cuda_ctx.compute_stream);
      mt.scheduleCopyBack(cuda_ctx.compute_stream);
    }
    cuda_ctx.recordStopEvent();
  }

  bool validSecretKey() { return sk.verifyCpuData(); }
  bool validPublicKey() { return pk.verifyCpuData(); }
  bool validMerkleRoots() { return mt.verifyCpuData(); }

  bool ready() { return cuda_ctx.eventTriggered(); }
  void printTiming() {}

  MemoryWindow memoryWindow(CudaSigner::MemoryWindowKind kind,
                            CudaSigner::MemoryWindowDevice device) {
    switch (kind) {
      case SK:
        if (device == Host) {
          return MemoryWindow{sk.secrets_h->data(),
                              safe_convert(ARRAY_TYPE_SZ(*sk.secrets_h) *
                                           sk.secrets_h->size())};
        } else {
          return MemoryWindow{sk.secrets_d->data(),
                              safe_convert(ARRAY_TYPE_SZ(*sk.secrets_d) *
                                           sk.secrets_d->size())};
        }
      case PK:
        if (device == Host) {
          return MemoryWindow{pk.eddsa_hashes_h.get(),
                              safe_convert(sizeof(*pk.eddsa_hashes_h))};
        } else {
          return MemoryWindow{pk.eddsa_hashes_d.get(),
                              safe_convert(sizeof(*pk.eddsa_hashes_d))};
        }
      case MT:
        if (device == Host) {
          return MemoryWindow{
              mt.nodes_h->data(),
              safe_convert(ARRAY_TYPE_SZ(*mt.nodes_h) * mt.nodes_h->size())};
        } else {
          return MemoryWindow{
              mt.nodes_d->data(),
              safe_convert(ARRAY_TYPE_SZ(*mt.nodes_d) * mt.nodes_d->size())};
        }
      default:
        throw std::runtime_error("Unreachable!");
    }
  }

 private:
  uint32_t safe_convert(size_t from) {
    if (from > 4294967295) {
      throw std::runtime_error("MemoryWindow exceeds 2GiB length");
    }
    return static_cast<uint32_t>(from);
  }

  cuda::SecretKeyInternal sk;
  cuda::PublicKeyInternal pk;
  cuda::MerkleTreeInternal mt;
};

void CudaSigner::pimpl_deleter::operator()(CudaSigner::pimpl* ptr) const {
  delete ptr;
}

CudaSigner::CudaSigner(Seed const& seed, cuda::HostAllocator& host_alloc,
                       cuda::DeviceAllocator& gpu_alloc)
    : impl{std::unique_ptr<pimpl, pimpl_deleter>(
          new pimpl(seed, host_alloc, gpu_alloc), pimpl_deleter())} {}

void CudaSigner::reset(Seed const& s) { impl->reset(s); }
Seed const& CudaSigner::getSeed() const { return impl->getSeed(); }
void CudaSigner::scheduleCompute() { impl->scheduleCompute(); }

bool CudaSigner::validSecretKey() { return impl->validSecretKey(); }
bool CudaSigner::validPublicKey() { return impl->validPublicKey(); }
bool CudaSigner::validMerkleRoots() { return impl->validMerkleRoots(); }

bool CudaSigner::ready() { return impl->ready(); }

MemoryWindow CudaSigner::memoryWindow(CudaSigner::MemoryWindowKind kind,
                                      CudaSigner::MemoryWindowDevice device) {
  return impl->memoryWindow(kind, device);
}

}  // namespace dory::pony

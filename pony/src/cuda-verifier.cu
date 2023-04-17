#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>

#include "cuda-verifier.hpp"
#include "cuda/core.cuh"

#define ARRAY_TYPE_SZ(x) \
  sizeof(std::remove_reference_t<decltype(x)>::value_type)

namespace dory::pony {

class CudaVerifier::pimpl : private cuda::SignerVerifierBase {
 public:
  pimpl(cuda::HostAllocator& host_alloc, cuda::DeviceAllocator& gpu_alloc)
      : pk{nullptr, host_alloc, gpu_alloc}, mt{&pk, host_alloc, gpu_alloc} {}

  void reset() { cuda_ctx.resetStopEvent(); }

  void scheduleCompute() {
    if constexpr ((Scheme == HORS && hors::PkEmbedding == hors::Merkle) ||
                  (Scheme == WOTS && wots::VerifyOnGpu)) {
      pk.scheduleCopy(cuda_ctx.compute_stream);
    }
    if constexpr (Scheme == HORS && hors::PkEmbedding == hors::Merkle) {
      mt.schedulePopulate(cuda_ctx.compute_stream);
      mt.scheduleCopyBack(cuda_ctx.compute_stream);
    }
    cuda_ctx.recordStopEvent();
  }

  bool validMerkleRoots() { return mt.verifyCpuData(); }

  bool ready() { return cuda_ctx.eventTriggered(); }

  bool verify(WotsSignature const& sig, uint8_t const* msg,
              size_t const msg_len) {
    return pk.verify(sig, msg, msg_len, cuda_ctx.compute_stream);
  };

  void printTiming() {}

  MemoryWindow memoryWindow(CudaVerifier::MemoryWindowKind kind,
                            CudaVerifier::MemoryWindowDevice device) {
    switch (kind) {
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

  cuda::PublicKeyInternal pk;
  cuda::MerkleTreeInternal mt;
};

void CudaVerifier::pimpl_deleter::operator()(CudaVerifier::pimpl* ptr) const {
  delete ptr;
}

CudaVerifier::CudaVerifier(cuda::HostAllocator& host_alloc,
                           cuda::DeviceAllocator& gpu_alloc)
    : impl{std::unique_ptr<pimpl, pimpl_deleter>(
          new pimpl(host_alloc, gpu_alloc), pimpl_deleter())} {}

void CudaVerifier::reset() { impl->reset(); }
void CudaVerifier::scheduleCompute() { impl->scheduleCompute(); }

bool CudaVerifier::validMerkleRoots() { return impl->validMerkleRoots(); }

bool CudaVerifier::ready() { return impl->ready(); }

bool CudaVerifier::verify(WotsSignature const& sig, uint8_t const* msg,
                          size_t const msg_len) {
  return impl->verify(sig, msg, msg_len);
};

MemoryWindow CudaVerifier::memoryWindow(
    CudaVerifier::MemoryWindowKind kind,
    CudaVerifier::MemoryWindowDevice device) {
  return impl->memoryWindow(kind, device);
}

}  // namespace dory::pony

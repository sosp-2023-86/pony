#include <cuda.h>
#include <cuda_runtime.h>

#include <chrono>
#include <memory>

#include <fmt/core.h>

#include "crypto.hpp"

#include "cuda/check.cuh"
#include "cuda/core.cuh"
#include "cuda/cuda-raii.cuh"

namespace dory::pony {
struct CudaCrypto::pimpl {
  pimpl()
      : sk{makeUniqueCuda<cuda::SecretKey>()},
        seed{makeUniqueCuda<cuda::Seed>()},
        seed_host{std::make_unique<cuda::Seed>()} {}

  bool gpuWorks() { return cuda::invoke_cuda_test_kernel(false); }

  void prepareSeed() {
    *seed_host = {};
    cudaUniqueCpy(seed, seed_host);
  }

  void populateSk(bool measure_time = false) {
    std::chrono::time_point<std::chrono::steady_clock> start, done;

    if (measure_time) {
      start = std::chrono::steady_clock::now();
    }

    sk->populate(seed);
    cudaDeviceSynchronize();

    if (measure_time) {
      done = std::chrono::steady_clock::now();
      fmt::print(
          "SecretKey/PublicKey/MerkleTree populated in {}ns\n",
          std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
              .count());
    }
  }

  std::unique_ptr<cuda::SecretKey> getSk(bool measure_time = false) {
    std::chrono::time_point<std::chrono::steady_clock> start, done;

    auto sk_host_unpinned = std::make_unique<cuda::SecretKey>();
    if (measure_time) {
      start = std::chrono::steady_clock::now();
    }

    cudaUniqueCpy(sk_host_unpinned, sk);

    if (measure_time) {
      done = std::chrono::steady_clock::now();
      fmt::print(
          "Copied SK (unpinned) ({} bytes) in {}ns\n", sizeof(cuda::SecretKey),
          std::chrono::duration_cast<std::chrono::nanoseconds>(done - start)
              .count());
    }

    return sk_host_unpinned;
  }

  UniqueCudaPtr<cuda::SecretKey> sk;
  UniqueCudaPtr<cuda::Seed> seed;
  std::unique_ptr<cuda::Seed> seed_host;
};
void CudaCrypto::pimpl_deleter::operator()(CudaCrypto::pimpl *ptr) const {
  delete ptr;
}

CudaCrypto::CudaCrypto()
    : impl{std::unique_ptr<pimpl, pimpl_deleter>(new pimpl(),
                                                 pimpl_deleter())} {}

bool CudaCrypto::gpuWorks() { return impl->gpuWorks(); }

void CudaCrypto::run() {
  impl->prepareSeed();
  impl->populateSk(true);
  impl->getSk(true);
}
}  // namespace dory::pony

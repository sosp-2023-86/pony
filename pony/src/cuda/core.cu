#include <array>
#include <atomic>
#include <cstdint>
#include <memory>

#include <stdexcept>

#include <cuda.h>
#include <cuda_runtime.h>

#include <fmt/core.h>

#include "../config.hpp"
#include "../wots.hpp"
#include "core.cuh"
#include "util.cuh"

// There is a potential compiler bug that messes up dc (relocatable device
// code), especially when using templates. The current workaround avoid
// compiling blake3 in separate files, i.e., blake3.cu is missing from CMake.
#include "blake3.inc"

namespace dory::cuda {

static unsigned constexpr blocks(size_t const n) {
  return static_cast<unsigned>((n + ThreadsPerBlock - 1) / ThreadsPerBlock);
}

namespace dory::cuda::kernels {
__global__ void populate_sk(size_t const hashes, Seed const seed,
                            void* const secrets) {
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= hashes) {
    return;
  }
  blake3::hash<sizeof(Seed), true>(&seed,
                                   reinterpret_cast<blake3::Hash*>(secrets)[i],
                                   static_cast<uint32_t>(i));
}

__global__ void populate_pk(size_t const n, Secret const* const secrets,
                            blake3::Hash* const hashes) {
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) {
    return;
  }
  blake3::hash<sizeof(Secret)>(&secrets[i], hashes[i]);
}

__global__ void compute_mt_level(size_t const hashes,
                                 blake3::Hash const* const src,
                                 blake3::Hash* const dst) {
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= hashes) {
    return;
  }
  blake3::hash<sizeof(blake3::Hash[2])>(&src[i * 2], dst[i]);
}

__global__ void iterative_hash(size_t const n, blake3::Hash* const hashes,
                               size_t const* const nb_hashes) {
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) {
    return;
  }
  size_t const todo = nb_hashes[i];
  for (size_t j = 0; j < pony::SecretsDepth; j++) {
    if (j < todo) {
      blake3::hash<sizeof(blake3::Hash)>(&hashes[i], hashes[i]);
    }
  }
}

__global__ void same_hashes(size_t const n, blake3::Hash const* const h1,
                            blake3::Hash const* const h2, bool* valid) {
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) {
    return;
  }
  static_assert(sizeof(blake3::Hash) % sizeof(uint64_t) == 0);
  for (size_t j = 0; j < sizeof(blake3::Hash) / sizeof(uint64_t); j++) {
    if (reinterpret_cast<uint64_t const*>(h1 + i)[j] !=
        reinterpret_cast<uint64_t const*>(h2 + i)[j]) {
      *valid = false;
    }
  }
}
}  // namespace dory::cuda::kernels

SecretKeyInternal::SecretKeyInternal(Seed seed, HostAllocator& host_alloc,
                                     DeviceAllocator& gpu_alloc)
    : seed_h{seed},
      secrets_d{makeUnitializedUniqueCuda<
          std::array<std::array<Secret, Secrets>, SecretsDepth>>(gpu_alloc)},
      secrets_h{makeInitializedUniqueHost<
          std::array<std::array<Secret, Secrets>, SecretsDepth>>(host_alloc)} {}

void SecretKeyInternal::schedulePopulate(cudaStream_t& stream) {
  size_t constexpr BytesToGenerate = sizeof(Secret) * pony::SecretsPerSecretKey;
  if (BytesToGenerate % sizeof(blake3::Hash) != 0) {
    throw std::runtime_error(
        "The number of random bytes to generate should be divisible by "
        "`blake3::Hash`!");
  }
  auto constexpr Hashes = BytesToGenerate / sizeof(blake3::Hash);

  // fmt::print("Blocks {}, TpB {}, BytesToGenerate {}\n", blocks(hashes),
  // ThreadsPerBlock, BytesToGenerate);
  dory::cuda::kernels::
      populate_sk<<<blocks(Hashes), ThreadsPerBlock, 0, stream>>>(
          Hashes, seed_h, secrets_d->front().data());
  gpuErrchk(cudaPeekAtLastError());

  for (size_t depth = 1; depth < secrets_d->size(); depth++) {
    dory::cuda::kernels::
        populate_pk<<<blocks(Hashes), ThreadsPerBlock, 0, stream>>>(
            Hashes, (*secrets_d)[depth - 1].data(), (*secrets_d)[depth].data());
    gpuErrchk(cudaPeekAtLastError());
  }
}

void SecretKeyInternal::scheduleCopyBack(cudaStream_t& stream) {
  // fmt::print("SecretKey is {} bytes\n",
  // sizeof(decltype(secrets_d)::element_type));

  cudaError_t result =
      cudaMemcpyAsync(secrets_h->data(), secrets_d->data(),
                      sizeof(decltype(secrets_d)::element_type),
                      cudaMemcpyDeviceToHost, stream);
  gpuErrchk(result);
}

PublicKeyInternal::PublicKeyInternal(SecretKeyInternal* sk,
                                     HostAllocator& host_alloc,
                                     DeviceAllocator& gpu_alloc)
    : sk{sk},
      eddsa_hashes_d{makeUnitializedUniqueCuda<pony::PublicKey>(gpu_alloc)},
      eddsa_hashes_h{makeInitializedUniqueHost<pony::PublicKey>(host_alloc)},
      wots_io_d{makeUnitializedUniqueCuda<WotsVerificationIO>(gpu_alloc)} {}

void PublicKeyInternal::schedulePopulate(cudaStream_t& stream) {
  if (sk == nullptr) {
    throw std::runtime_error(fmt::format("Unsupported"));
  }

  // No need to populate the PK in WOTS as it is simply the last level of the SK
  if constexpr (pony::Scheme == pony::WOTS) {
    return;
  }

  dory::cuda::kernels::
      populate_pk<<<blocks(Hashes), ThreadsPerBlock, 0, stream>>>(
          Hashes, sk->secrets_d->back().data(), eddsa_hashes_d->hashes.data());
  gpuErrchk(cudaPeekAtLastError());
}

void PublicKeyInternal::scheduleCopyBack(cudaStream_t& stream) {
  // fmt::print("PublicKey is {} bytes\n", sizeof(eddsa_hashes_h->hashes));
  cudaError_t const result = [this, &stream]() {
    if constexpr (pony::Scheme == pony::WOTS) {
      // In the case of WOTS, we need to copy from the SK in host memory.
      return cudaMemcpyAsync(
          eddsa_hashes_h->hashes.data(), sk->secrets_h->back().data(),
          sizeof(eddsa_hashes_h->hashes), cudaMemcpyHostToHost, stream);
    } else {
      // In the case of HORS, we need to copy from the PK in device memory.
      return cudaMemcpyAsync(
          eddsa_hashes_h->hashes.data(), eddsa_hashes_d->hashes.data(),
          sizeof(eddsa_hashes_d->hashes), cudaMemcpyDeviceToHost, stream);
    }
  }();

  if (result != cudaSuccess) {
    throw std::runtime_error(
        fmt::format("CUDA Runtime Error: {}\n", cudaGetErrorString(result)));
  }
}

void PublicKeyInternal::scheduleCopy(cudaStream_t& stream) {
  // fmt::print("PublicKey is {} bytes\n", sizeof(eddsa_hashes_d->hashes));

  cudaError_t result = cudaMemcpyAsync(
      eddsa_hashes_d->hashes.data(), eddsa_hashes_h->hashes.data(),
      sizeof(eddsa_hashes_h->hashes), cudaMemcpyHostToDevice, stream);
  gpuErrchk(result);
}

bool PublicKeyInternal::verify(pony::WotsSignature const& sig,
                               uint8_t const* msg, size_t const msg_len,
                               cudaStream_t& stream) {
  WotsVerificationIO io;
  pony::WotsHash h(sig.pk_hash, sig.nonce, msg, msg + msg_len);
  for (size_t i = 0; i < Hashes; i++) {
    io.nb_hashes[i] = pony::SecretsDepth - h.getSecretDepth(i) - 1;
  }
  io.secrets = sig.secrets;
  io.valid = true;
  {
    cudaError_t result = cudaMemcpyAsync(wots_io_d.get(), &io, sizeof(io),
                                         cudaMemcpyHostToDevice, stream);
    if (result != cudaSuccess) {
      throw std::runtime_error(
          fmt::format("CUDA Runtime Error: {}\n", cudaGetErrorString(result)));
    }
  }
  dory::cuda::kernels::
      iterative_hash<<<blocks(Hashes), ThreadsPerBlock, 0, stream>>>(
          Hashes, wots_io_d->secrets.data(), wots_io_d->nb_hashes.data());
  gpuErrchk(cudaPeekAtLastError());
  dory::cuda::kernels::
      same_hashes<<<blocks(Hashes), ThreadsPerBlock, 0, stream>>>(
          Hashes, wots_io_d->secrets.data(), eddsa_hashes_d->hashes.data(),
          &wots_io_d->valid);
  gpuErrchk(cudaPeekAtLastError());
  {
    cudaError_t result =
        cudaMemcpyAsync(&io.valid, &wots_io_d->valid, sizeof(io.valid),
                        cudaMemcpyDeviceToHost, stream);
    if (result != cudaSuccess) {
      throw std::runtime_error(
          fmt::format("CUDA Runtime Error: {}\n", cudaGetErrorString(result)));
    }
  }
  cudaStreamSynchronize(stream);
  return io.valid;
}

MerkleTreeInternal::MerkleTreeInternal(PublicKeyInternal* pk,
                                       HostAllocator& host_alloc,
                                       DeviceAllocator& gpu_alloc)
    : pk{pk},
      nodes_d{makeUnitializedUniqueCuda<std::array<blake3::Hash, Nodes>>(
          gpu_alloc)},
      nodes_h{makeInitializedUniqueHost<std::array<blake3::Hash, Nodes>>(
          host_alloc)} {}

void MerkleTreeInternal::schedulePopulate(cudaStream_t& stream) {
  // Let's compute the MT in parallel at each level.
  size_t nodes_this_level = (Nodes + 1) / 2;
  blake3::Hash const* src = pk->eddsa_hashes_d->hashes.data();
  blake3::Hash* dst = &(*nodes_d)[Nodes];
  while (true) {
    dst -= nodes_this_level;

    // fmt::print("Blocks {}, TpB {}\n", blocks(nodes_this_level),
    // ThreadsPerBlock);
    dory::cuda::kernels::compute_mt_level<<<blocks(nodes_this_level),
                                            ThreadsPerBlock, 0, stream>>>(
        nodes_this_level, src, dst);
    gpuErrchk(cudaPeekAtLastError());

    // if (nodes_this_level == 1) {
    if (nodes_this_level == pony::hors::NbRoots) {
      break;
    }

    src = dst;
    nodes_this_level /= 2;
  };
}

void MerkleTreeInternal::scheduleCopyBack(cudaStream_t& stream) {
  // fmt::print("MerkleTree is {} bytes\n",
  // sizeof(decltype(nodes_d)::element_type));

  cudaError_t result = cudaMemcpyAsync(nodes_h->data(), nodes_d->data(),
                                       sizeof(decltype(nodes_d)::element_type),
                                       cudaMemcpyDeviceToHost, stream);
  gpuErrchk(result);
}

}  // namespace dory::cuda

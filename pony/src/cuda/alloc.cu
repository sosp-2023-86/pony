#include <cstdlib>
#include <stdexcept>

#include <cuda.h>
#include <cuda_runtime.h>

#include <fmt/core.h>

#include "alloc.cuh"

namespace dory::cuda {
GpuCudaAllocator::GpuCudaAllocator(size_t bytes) : ArenaAllocator(bytes) {
  cudaError_t result = cudaMalloc(&data, sz);

  if (result != cudaSuccess) {
    throw std::runtime_error(fmt::format("Could not allocate CUDA memory: {}\n",
                                         cudaGetErrorString(result)));
  }

  p = data;
}

GpuCudaAllocator::~GpuCudaAllocator() noexcept(false) {
  if (data) {
    cudaError_t result = cudaFree(data);

    if (result != cudaSuccess) {
      throw std::runtime_error(fmt::format("Could not free CUDA memory: {}\n",
                                           cudaGetErrorString(result)));
    }
  }
}

GpuNormalAllocator::GpuNormalAllocator(size_t bytes) : ArenaAllocator(bytes) {
  auto ptr = std::malloc(sz);

  if (!ptr) {
    throw std::runtime_error("Could not allocate CUDA memory using malloc\n");
  }

  data = reinterpret_cast<decltype(data)>(ptr);
  p = data;
}

GpuNormalAllocator::~GpuNormalAllocator() noexcept(false) { std::free(data); }

HostCudaAllocator::HostCudaAllocator(size_t bytes) : ArenaAllocator(bytes) {
  cudaError_t result = cudaMallocHost(&data, sz);

  if (result != cudaSuccess) {
    throw std::runtime_error(fmt::format("Could not allocate HOST memory: {}\n",
                                         cudaGetErrorString(result)));
  }

  p = data;
}

HostCudaAllocator::~HostCudaAllocator() noexcept(false) {
  if (data) {
    cudaError_t result = cudaFreeHost(data);

    if (result != cudaSuccess) {
      throw std::runtime_error(fmt::format("Could not free HOST memory: {}\n",
                                           cudaGetErrorString(result)));
    }
  }
}

HostNormalAllocator::HostNormalAllocator(size_t bytes) : ArenaAllocator(bytes) {
  auto ptr = std::malloc(sz);

  if (!ptr) {
    throw std::runtime_error("Could not allocate HOST memory using malloc\n");
  }

  data = reinterpret_cast<decltype(data)>(ptr);
  p = data;
}

HostNormalAllocator::~HostNormalAllocator() noexcept(false) { std::free(data); }

}  // namespace dory::cuda

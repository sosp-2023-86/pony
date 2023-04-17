#include <cstdio>
#include <stdexcept>

#include <fmt/core.h>

#include <cuda.h>
#include <cuda_runtime.h>

#include "check.cuh"
#include "util.cuh"

__global__ void cuda_check_kernel_invocation(bool print) {
  if (print) {
    printf("GPU kernel invocation works!\n");
  }
}

namespace dory::cuda {
bool works(bool print) {
  cudaError_t err;

  cuda_check_kernel_invocation<<<1, 1>>>(print);

  err = cudaPeekAtLastError();
  gpuAssert(err, __FILE__, __LINE__, false);
  if (err != cudaSuccess) {
    return false;
  }

  err = cudaDeviceSynchronize();
  gpuAssert(err, __FILE__, __LINE__, false);
  if (err != cudaSuccess) {
    return false;
  }

  return true;
}

bool have_gpu() {
  int deviceCount = 0;
  CUresult error;

  error = cuInit(0);
  if (error != CUDA_SUCCESS) {
    return false;
  }

  error = cuDeviceGetCount(&deviceCount);
  if (error != CUDA_SUCCESS) {
    throw std::runtime_error(
        fmt::format("Failed to query the number of CUDA devices ({})\n",
                    static_cast<int>(error)));
  }

  return deviceCount > 0;
}
}  // namespace dory::cuda

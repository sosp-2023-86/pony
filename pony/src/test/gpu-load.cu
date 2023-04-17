#include <array>
#include <atomic>
#include <cstdint>
#include <memory>

#include <stdexcept>

#include <cuda.h>
#include <cuda_runtime.h>

#include <fmt/core.h>

#include <lyra/lyra.hpp>

#include "../cuda/util.cuh"

__global__ void add(bool forever, uint64_t *a, uint64_t *b, uint64_t *c,
                       int n) {
  int id = blockIdx.x * blockDim.x + threadIdx.x;

  if (id < n) {
    // while (forever) {
    for (int i = 0; i < 1024 * 1024; i++) {
      c[id] = a[id] + b[id];
    }
  }
}

// you must first call the cudaGetDeviceProperties() function, then pass 
// the devProp structure returned to this function:
int getSPcores(cudaDeviceProp &devProp)
{  
    int cores = 0;
    int mp = devProp.multiProcessorCount;
    switch (devProp.major){
     case 2: // Fermi
      if (devProp.minor == 1) cores = mp * 48;
      else cores = mp * 32;
      break;
     case 3: // Kepler
      cores = mp * 192;
      break;
     case 5: // Maxwell
      cores = mp * 128;
      break;
     case 6: // Pascal
      if ((devProp.minor == 1) || (devProp.minor == 2)) cores = mp * 128;
      else if (devProp.minor == 0) cores = mp * 64;
      else printf("Unknown device type\n");
      break;
     case 7: // Volta and Turing
      if ((devProp.minor == 0) || (devProp.minor == 5)) cores = mp * 64;
      else printf("Unknown device type\n");
      break;
     case 8: // Ampere
      if (devProp.minor == 0) cores = mp * 64;
      else if (devProp.minor == 6) cores = mp * 128;
      else if (devProp.minor == 9) cores = mp * 128; // ada lovelace
      else printf("Unknown device type\n");
      break;
     case 9: // Hopper
      if (devProp.minor == 0) cores = mp * 128;
      else printf("Unknown device type\n");
      break;
     default:
      printf("Unknown device type\n"); 
      break;
      }
    return cores;
}


int main(int argc, char *argv[]) {
  lyra::cli cli;

  bool get_help = false;
  int load_percentage;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(load_percentage, "num")
                        .required()
                        .name("-l")
                        .name("--load-percentage")
                        .help("Percentage of CUDA cores occupied"));

  // Parse the program arguments.
  auto result = cli.parse({argc, argv});

  if (get_help) {
    std::cout << cli;
    return 0;
  }

  if (!result) {
    std::cerr << "Error in command line: " << result.errorMessage()
              << std::endl;
    return 1;
  }

  if (load_percentage < 0 || load_percentage > 100) {
    std::cerr << "Load percentage must be between 1 and 100" << std::endl;
    return 1;
  }

  int nDevices;
  gpuErrchk(cudaGetDeviceCount(&nDevices));

  if (nDevices != 1) {
    std::cerr << "Only a single GPU is supported" << std::endl;
  }

  cudaDeviceProp prop;
  int dev = 0; // First device
  gpuErrchk(cudaGetDeviceProperties(&prop, dev));
  fmt::print("Device Number: {}\n", dev);
  fmt::print("  Device name: {}\n", prop.name);
  fmt::print("  Memory Clock Rate (KHz): {}\n",
          prop.memoryClockRate);
  fmt::print("  Memory Bus Width (bits): {}\n",
          prop.memoryBusWidth);
  fmt::print("  Peak Memory Bandwidth (GB/s): {}\n\n",
          2.0 * prop.memoryClockRate * (prop.memoryBusWidth / 8) / 1.0e6);
  
  auto total_cuda_cores = getSPcores(prop);
  
  fmt::print("GPU device has {} CUDA cores\n", total_cuda_cores);

  size_t arr_sz = total_cuda_cores;

  auto h_a = std::make_unique<uint64_t[]>(arr_sz);
  auto h_b = std::make_unique<uint64_t[]>(arr_sz);
  auto h_c = std::make_unique<uint64_t[]>(arr_sz);

  // Initialize vectors on host
  for (size_t i = 0; i < arr_sz; i++) {
    h_a[i] = i * i;
    h_b[i] = (i+1) * (i+1);
  }

  uint64_t *d_a;
  uint64_t *d_b;
  uint64_t *d_c;

  auto bytes = arr_sz * sizeof(uint64_t);
  gpuErrchk(cudaMalloc(&d_a, bytes));
  gpuErrchk(cudaMalloc(&d_b, bytes));
  gpuErrchk(cudaMalloc(&d_c, bytes));

  gpuErrchk(cudaMemcpy(d_a, h_a.get(), bytes, cudaMemcpyHostToDevice));
  gpuErrchk(cudaMemcpy(d_b, h_b.get(), bytes, cudaMemcpyHostToDevice));


  // Execute the kernel
  // Pass the forever flag from the argument list to prevent
  // the optimizer from phasing it out
  auto used_cuda_cores = std::clamp(static_cast<int>(load_percentage / 100.0 * total_cuda_cores), 0, total_cuda_cores);
  fmt::print("Using {}/{} CUDA cores\n", used_cuda_cores, total_cuda_cores);
  

//     blockSize = 1024;
//    
//       // Number of thread blocks in grid
//     gridSize = (int)ceil((float)n / blockSize);

  add<<<26,128>>>(false, d_a, d_b, d_c, total_cuda_cores);
  gpuErrchk(cudaPeekAtLastError());

  gpuErrchk(cudaDeviceSynchronize());


  return 0;
}

//    
//       // Copy host vectors to device

//    
//     int blockSize, gridSize;
//    
//       // Number of threads in each thread block
//     blockSize = 1024;
//    
//       // Number of thread blocks in grid
//     gridSize = (int)ceil((float)n / blockSize);
//    
//       // Execute the kernel
//     vecAdd<<<gridSize, blockSize>>>(d_a, d_b, d_c, n);
//    
//       // Copy array back to host
//     cudaMemcpy(h_c, d_c, bytes, cudaMemcpyDeviceToHost);
//    
//       // Sum up vector c and print result divided by n, this should equal 1 within error
//     double sum = 0;
//       for (i = 0; i < n; i++)
//         sum += h_c[i];
//       printf("final result: %f\n", sum / n);
//    
//       // Release device memory
//     cudaFree(d_a);
//       cudaFree(d_b);
//       cudaFree(d_c);
//    
//       // Release host memory
//     free(h_a);
//       free(h_b);
//       free(h_c);
//    
//     return 0;
// }

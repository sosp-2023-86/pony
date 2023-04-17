#include <chrono>
#include <deque>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include "../cuda/alloc.cuh"
#include "../cuda/core.cuh"
#include "../export/config.hpp"
#include "../mock-signer.hpp"

using namespace dory;

int main(int argc, char *argv[]) {
  lyra::cli cli;

  bool get_help = false;
  size_t concurrency = 4;
  size_t depth = 2048;

  cli.add_argument(lyra::help(get_help))
      .add_argument(
          lyra::opt(concurrency, "concurrency")
              .name("-c")
              .name("--concurrency")
              .help("Number of concurrent CUDA object being populated/copied"))
      .add_argument(
          lyra::opt(depth, "depth")
              .name("-d")
              .name("--depth")
              .help("How many times an object should be populated/copied"));

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

  fmt::print("[SECRETS/SK={}, PK={}B, CONCURRENCY={}, DEPTH={}]\n",
             pony::SecretsPerSecretKey, sizeof(pony::PublicKey), concurrency,
             depth);

  size_t static constexpr GB = 1024 * 1024 * 1024;
  cuda::HostNormalAllocator host_alloc(1 * GB);
  cuda::GpuCudaAllocator gpu_alloc(1 * GB);

  std::deque<cuda::SecretKeyInternal> sks;
  std::deque<cuda::PublicKeyInternal> pks;
  std::deque<cuda::MerkleTreeInternal> mts;
  std::deque<cudaStream_t> streams;

  cuda::Seed seed = {};
  pony::CpuMockSigner cpu_signer(seed, host_alloc);

  for (size_t i = 0; i < concurrency; i++) {
    sks.emplace_back(seed, host_alloc, gpu_alloc);
    pks.emplace_back(&sks.back(), host_alloc, gpu_alloc);
    mts.emplace_back(&pks.back(), host_alloc, gpu_alloc);
    {
      streams.emplace_back();
      gpuErrchk(cudaStreamCreate(&streams.back()));
    }
  }
  {
    auto const start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < depth; i++) {
      for (size_t c = 0; c < concurrency; c++) {
        sks[c].schedulePopulate(streams[c]);
      }
    }
    cudaDeviceSynchronize();
    auto const end = std::chrono::steady_clock::now();
    fmt::print("[SK][GPU][POPULATE] {}/s\n", depth * concurrency * 1000 * 1000 *
                                                 1000 / (end - start).count());
    gpuErrchk(cudaPeekAtLastError());
  }
  {
    auto const start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < depth; i++) {
      for (size_t c = 0; c < concurrency; c++) {
        sks[c].scheduleCopyBack(streams[c]);
      }
    }
    cudaDeviceSynchronize();
    auto const end = std::chrono::steady_clock::now();
    fmt::print(
        "[SK][GPU][COPY_BACK] {}/s\n",
        depth * concurrency * 1000 * 1000 * 1000 / (end - start).count());
  }
  {
    auto const start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < depth; i++) {
      for (size_t c = 0; c < concurrency; c++) {
        pks[c].schedulePopulate(streams[c]);
      }
    }
    cudaDeviceSynchronize();
    auto const end = std::chrono::steady_clock::now();
    fmt::print("[PK][GPU][POPULATE] {}/s\n", depth * concurrency * 1000 * 1000 *
                                                 1000 / (end - start).count());
  }
  {
    auto const start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < depth; i++) {
      for (size_t c = 0; c < concurrency; c++) {
        pks[c].scheduleCopyBack(streams[c]);
      }
    }
    cudaDeviceSynchronize();
    auto const end = std::chrono::steady_clock::now();
    fmt::print(
        "[PK][GPU][COPY_BACK] {}/s\n",
        depth * concurrency * 1000 * 1000 * 1000 / (end - start).count());
  }
  if (pony::Scheme == pony::HORS &&
      pony::hors::PkEmbedding == pony::hors::Merkle) {
    {
      auto const start = std::chrono::steady_clock::now();
      for (size_t i = 0; i < depth; i++) {
        for (size_t c = 0; c < concurrency; c++) {
          mts[c].schedulePopulate(streams[c]);
        }
      }
      cudaDeviceSynchronize();
      auto const end = std::chrono::steady_clock::now();
      fmt::print(
          "[MT][GPU][POPULATE] {}/s\n",
          depth * concurrency * 1000 * 1000 * 1000 / (end - start).count());
    }
    {
      auto const start = std::chrono::steady_clock::now();
      for (size_t i = 0; i < depth; i++) {
        for (size_t c = 0; c < concurrency; c++) {
          mts[c].scheduleCopyBack(streams[c]);
        }
      }
      cudaDeviceSynchronize();
      auto const end = std::chrono::steady_clock::now();
      fmt::print(
          "[MT][GPU][COPY_BACK] {}/s\n",
          depth * concurrency * 1000 * 1000 * 1000 / (end - start).count());
    }
  }
  {
    auto const start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < depth; i++) {
      for (size_t c = 0; c < concurrency; c++) {
        cpu_signer.generate_secrets();
      }
    }
    auto const end = std::chrono::steady_clock::now();
    fmt::print("[SK][CPU][POPULATE] {}/s\n", depth * concurrency * 1000 * 1000 *
                                                 1000 / (end - start).count());
  }
  {
    auto const start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < depth; i++) {
      for (size_t c = 0; c < concurrency; c++) {
        cpu_signer.generate_public_key();
      }
    }
    auto const end = std::chrono::steady_clock::now();
    fmt::print("[PK][CPU][POPULATE] {}/s\n", depth * concurrency * 1000 * 1000 *
                                                 1000 / (end - start).count());
  }
  if (pony::Scheme == pony::HORS &&
      pony::hors::PkEmbedding == pony::hors::Merkle) {
    {
      auto const start = std::chrono::steady_clock::now();
      for (size_t i = 0; i < depth; i++) {
        for (size_t c = 0; c < concurrency; c++) {
          cpu_signer.generate_merkle_tree();
        }
      }
      auto const end = std::chrono::steady_clock::now();
      fmt::print(
          "[MT][CPU][POPULATE] {}/s\n",
          depth * concurrency * 1000 * 1000 * 1000 / (end - start).count());
    }
  }

  fmt::print("###DONE###\n");
  return 0;
}

#pragma once

#include <memory>
#include <type_traits>

// todo: Factorize UniqueCudaPtr and UniqueCudaHostPtr with a template.

// Device
struct CudaDeleter {
  void operator()(void* p) { cudaFree(p); }
};

template <class T>
using UniqueCudaPtr = std::unique_ptr<T, CudaDeleter>;

template <class T, std::enable_if_t<std::is_array<T>::value, bool> = true>
__host__ UniqueCudaPtr<T> makeUniqueCuda(size_t const n) {
  using ElementType = typename std::remove_all_extents<T>::type;
  ElementType* raw_cuda_ptr;
  cudaMalloc(&raw_cuda_ptr, n * sizeof(ElementType));
  return UniqueCudaPtr<T>(raw_cuda_ptr);
}

template <class T>
__host__ UniqueCudaPtr<T> makeUniqueCuda(/* todo: forward */) {
  T* raw_cuda_ptr;
  cudaMalloc(&raw_cuda_ptr, sizeof(T));
  return UniqueCudaPtr<T>(raw_cuda_ptr);
}

// Host
struct CudaHostDeleter {
  void operator()(void* p) { cudaFreeHost(p); }
};

// Version for pinned memory
template <class T>
using UniqueCudaHostPtr = std::unique_ptr<T, CudaHostDeleter>;

template <class T, std::enable_if_t<std::is_array<T>::value, bool> = true>
__host__ UniqueCudaHostPtr<T> makeUniqueCudaHost(size_t const n) {
  using ElementType = typename std::remove_all_extents<T>::type;
  ElementType* raw_cuda_ptr;
  cudaMallocHost(&raw_cuda_ptr, n * sizeof(ElementType));
  return UniqueCudaHostPtr<T>(raw_cuda_ptr);
}

template <class T>
__host__ UniqueCudaHostPtr<T> makeUniqueCudaHost(/* todo: forward */) {
  T* raw_cuda_ptr;
  cudaMallocHost(&raw_cuda_ptr, sizeof(T));
  return UniqueCudaHostPtr<T>(raw_cuda_ptr);
}

// Helpers to copy between host and device using unique pointers
template <class T>
void cudaUniqueCpy(std::unique_ptr<T[]> const& dst,
                   UniqueCudaPtr<T[]> const& src, size_t const n) {
  cudaMemcpy(dst.get(), src.get(), n * sizeof(T), cudaMemcpyDeviceToHost);
}

template <class T>
void cudaUniqueCpy(UniqueCudaPtr<T[]> const& dst,
                   std::unique_ptr<T[]> const& src, size_t const n) {
  cudaMemcpy(dst.get(), src.get(), n * sizeof(T), cudaMemcpyHostToDevice);
}

template <class T, std::enable_if_t<!std::is_array<T>::value, bool> = true>
void cudaUniqueCpy(std::unique_ptr<T> const& dst, UniqueCudaPtr<T> const& src) {
  cudaMemcpy(dst.get(), src.get(), sizeof(T), cudaMemcpyDeviceToHost);
}

template <class T, std::enable_if_t<!std::is_array<T>::value, bool> = true>
void cudaUniqueCpy(UniqueCudaPtr<T> const& dst, std::unique_ptr<T> const& src) {
  cudaMemcpy(dst.get(), src.get(), sizeof(T), cudaMemcpyHostToDevice);
}

// CudaHost version
template <class T>
void cudaUniqueCpy(UniqueCudaHostPtr<T[]> const& dst,
                   UniqueCudaPtr<T[]> const& src, size_t const n) {
  cudaMemcpy(dst.get(), src.get(), n * sizeof(T), cudaMemcpyDeviceToHost);
}

template <class T>
void cudaUniqueCpy(UniqueCudaPtr<T[]> const& dst,
                   UniqueCudaHostPtr<T[]> const& src, size_t const n) {
  cudaMemcpy(dst.get(), src.get(), n * sizeof(T), cudaMemcpyHostToDevice);
}

template <class T, std::enable_if_t<!std::is_array<T>::value, bool> = true>
void cudaUniqueCpy(UniqueCudaHostPtr<T> const& dst,
                   UniqueCudaPtr<T> const& src) {
  cudaMemcpy(dst.get(), src.get(), sizeof(T), cudaMemcpyDeviceToHost);
}

template <class T, std::enable_if_t<!std::is_array<T>::value, bool> = true>
void cudaUniqueCpy(UniqueCudaPtr<T> const& dst,
                   UniqueCudaHostPtr<T> const& src) {
  cudaMemcpy(dst.get(), src.get(), sizeof(T), cudaMemcpyHostToDevice);
}

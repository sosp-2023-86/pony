#pragma once

#include <cstddef>
#include <functional>
#include <memory>

#define CACHE_LINE_SIZE 64

namespace dory::cuda {

template <bool placement_new>
struct ArenaAllocator {
 protected:
  ArenaAllocator(size_t bytes) : data{nullptr}, p{nullptr}, sz(bytes) {}

 public:
  virtual ~ArenaAllocator() noexcept(false) {}

  ArenaAllocator(ArenaAllocator const &other) = delete;
  ArenaAllocator &operator=(ArenaAllocator const &other) = delete;

  template <typename T, typename... Args>
  T *aligned_alloc(Args &&... args) {
    // std::size_t a = alignof(T);
    std::size_t a = CACHE_LINE_SIZE;
    if (std::align(a, sizeof(T), p, sz)) {
      T *result = reinterpret_cast<T *>(p);
      if constexpr (placement_new) {
        // Placement new doesn't work, because the CPU cannot access GPU memory
        new (result) T(std::forward<Args>(args)...);
      }
      p = reinterpret_cast<uint8_t *>(p) + sizeof(T);
      sz -= sizeof(T);
      return result;
    }
    return nullptr;
  }

  template <typename T>
  void destroy(T *t) {}

  size_t size() const { return sz; }
  void *start() const { return p; }

 protected:
  uint8_t *data;
  void *p;
  size_t sz;
};

using HostAllocator = ArenaAllocator<true>;
using DeviceAllocator = ArenaAllocator<false>;

struct GpuCudaAllocator : public DeviceAllocator {
  GpuCudaAllocator(size_t bytes);
  ~GpuCudaAllocator() noexcept(false);
};

struct GpuNormalAllocator : public DeviceAllocator {
  GpuNormalAllocator(size_t bytes);
  ~GpuNormalAllocator() noexcept(false);
};

struct HostCudaAllocator : public HostAllocator {
  HostCudaAllocator(size_t bytes);
  ~HostCudaAllocator() noexcept(false);
};

struct HostNormalAllocator : public HostAllocator {
  HostNormalAllocator(size_t bytes);
  ~HostNormalAllocator() noexcept(false);
};

template <class T>
void no_deleter(T *t) {}

template <class T>
using UninitializedUniqueCudaPtr = std::unique_ptr<T, std::function<void(T *)>>;

template <class T>
using InitializedUniqueHostPtr = std::unique_ptr<T, std::function<void(T *)>>;

template <typename T, typename... Args>
UninitializedUniqueCudaPtr<T> makeUnitializedUniqueCuda(
    DeviceAllocator &alloc) {
  auto *t = alloc.aligned_alloc<T>();
  if (!t) {
    throw std::runtime_error("Gpu allocator ran out of memory");
  }

  auto deleter = [&alloc](T *t) { alloc.destroy(t); };

  return UninitializedUniqueCudaPtr<T>(t, deleter);
  // return UninitializedUniqueCudaPtr<T>(t, no_deleter<T>);
}

template <typename T, typename... Args>
InitializedUniqueHostPtr<T> makeInitializedUniqueHost(HostAllocator &alloc,
                                                      Args &&... args) {
  auto *t = alloc.aligned_alloc<T>(std::forward<Args>(args)...);
  if (!t) {
    throw std::runtime_error("Host allocator ran out of memory");
  }

  auto deleter = [&alloc](T *t) { alloc.destroy(t); };

  return InitializedUniqueHostPtr<T>(t, deleter);
  // return InitializedUniqueHostPtr<T>(t, no_deleter<T>);
}

}  // namespace dory::cuda

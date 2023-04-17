#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>

/**
 * @brief A pool that (dynamically) preallocates N elements of type T in device.
 *        Provides RAII-powered Unique pointers to the on-device elements.
 *
 * It maintains a linked list of available elements.
 *
 * @tparam T
 * @tparam N
 */
template <typename T, size_t N>
struct DevicePool {
  DevicePool() {
    cudaMalloc(&elements, sizeof(T) * N);
    for (size_t i = 0; i < linked_pointers.size(); i++) {
      linked_pointers[i].next = &linked_pointers[i + 1];
      linked_pointers[i].pointer = &elements[i];
    }
    linked_pointers.back().next = nullptr;
    next_pointer = &linked_pointers[0];
  }
  DevicePool(DevicePool&&) = delete;
  DevicePool(DevicePool const&) = delete;
  DevicePool& operator=(DevicePool&&) = delete;
  DevicePool& operator=(DevicePool const&) = delete;

  struct LinkedPointer {
    LinkedPointer* next;
    T* pointer;
  };

  T* elements;
  std::array<LinkedPointer, N> linked_pointers;
  std::mutex mutex;
  LinkedPointer* next_pointer;

  struct Unique {
    Unique(LinkedPointer* const lp, DevicePool& dp) : lp{lp}, dp{dp} {}
    Unique(Unique&& o) : lp{o.lp}, dp{o.dp} { o.moved = true; }
    Unique(Unique const&) = delete;
    Unique& operator=(Unique&&) = delete;
    Unique& operator=(Unique const&) = delete;
    ~Unique() {
      if (!moved) {
        dp.release(lp);
      }
    }

    T* get() const { return lp->pointer; }

    LinkedPointer* const lp;
    DevicePool& dp;
    bool moved = false;
  };

  Unique get() {
    while (true) {
      std::scoped_lock<std::mutex> lk(mutex);
      if (next_pointer == nullptr) {
        continue;
      }
      auto const lp = next_pointer;
      next_pointer = lp->next;
      return Unique(lp, *this);
    }
  }

  void release(LinkedPointer* const lp) {
    std::scoped_lock<std::mutex> lk(mutex);
    lp->next = next_pointer;
    next_pointer = lp;
  }
};

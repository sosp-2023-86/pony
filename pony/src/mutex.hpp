#pragma once

#include <atomic>
#include <mutex>

#include <dory/shared/branching.hpp>

namespace dory::pony {

// Implements the Lockable interface so that it is compatible with ScopedLock
class SpinMutex {
  SpinMutex(SpinMutex const&) = delete;
  SpinMutex& operator=(SpinMutex const&) = delete;
  SpinMutex(SpinMutex&&) = delete;
  SpinMutex& operator=(SpinMutex&&) = delete;

 public:
  SpinMutex() {}

  inline bool try_lock() {
    return flag.test_and_set(std::memory_order_acquire) == 0;
  }

  inline void lock() {
    while (unlikely(!try_lock()))
      ;
  }

  inline void unlock() { flag.clear(std::memory_order_release); }

 private:
  std::atomic_flag flag = ATOMIC_FLAG_INIT;
};

// using Mutex = std::mutex;
using Mutex = SpinMutex;

}  // namespace dory::pony

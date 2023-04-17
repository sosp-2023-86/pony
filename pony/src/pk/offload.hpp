#pragma once

#include <chrono>

#include "../types.hpp"

namespace dory::pony {
class PkOffload {
 public:
  enum MemoryWindowKind { PK, MT };
  enum MemoryWindowDevice { Host, Device };

  virtual void reset() = 0;
  virtual void scheduleCompute() = 0;
  virtual bool ready() = 0;

  virtual bool verify(WotsSignature const& sig, uint8_t const* msg,
                      size_t const msg_len) = 0;

  virtual bool validMerkleRoots() = 0;

  virtual MemoryWindow memoryWindow(MemoryWindowKind kind,
                                    MemoryWindowDevice device) = 0;

  virtual ~PkOffload() {}
};
}  // namespace dory::pony

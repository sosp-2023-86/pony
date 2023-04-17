#pragma once

#include <chrono>

#include "../types.hpp"

namespace dory::pony {
class SkOffload {
 public:
  enum MemoryWindowKind { SK, PK, MT };
  enum MemoryWindowDevice { Host, Device };

  virtual void reset(Seed const& s) = 0;
  virtual Seed const& getSeed() const = 0;
  virtual void scheduleCompute() = 0;
  virtual bool ready() = 0;

  virtual bool validSecretKey() = 0;
  virtual bool validPublicKey() = 0;
  virtual bool validMerkleRoots() = 0;

  virtual MemoryWindow memoryWindow(MemoryWindowKind kind,
                                    MemoryWindowDevice device) = 0;

  virtual ~SkOffload() {}
};
}  // namespace dory::pony

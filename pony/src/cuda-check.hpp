#pragma once

#include "cuda/check.inc"

namespace dory::pony {
static inline bool cuda_works(bool print) { return cuda::works(print); }
}  // namespace dory::pony

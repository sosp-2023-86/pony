#pragma once

#include "export/config.hpp"

#include <dory/shared/units.hpp>

namespace dory::pony {

char constexpr nspace[] = "pony-";

size_t constexpr AllocatedSize = dory::units::gibibytes(4);
size_t constexpr Alignment = 64;

size_t constexpr BufferedPksPerProcess = 2 * SkCtxs;
size_t constexpr PkCtxsPerProcess = 2 * BufferedPksPerProcess;
static_assert(PkCtxsPerProcess > BufferedPksPerProcess);  // Outstanding RECVs

}  // namespace dory::pony

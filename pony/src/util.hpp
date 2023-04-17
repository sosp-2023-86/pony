#pragma once

#include <xxhash.h>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

#include <fmt/core.h>

#include "types.hpp"

namespace dory::pony::logging {
static uint64_t memory_window_checksum(MemoryWindow const &mw) {
  return XXH3_64bits(mw.p, mw.sz);
}

template <typename T>
static std::string array_first_last(T const &t) {
  return fmt::format("{{{}, ..., {}}}", t.front(), t.back());
}

static std::string public_key(void *p) {
  auto *pk = reinterpret_cast<PublicKey *>(p);

  if constexpr (PresendEddsaOnly) {
    return fmt::format("EddsaOnlyPk[hash: {}, sig: {}]",
                       array_first_last(pk->hash),
                       array_first_last(pk->sig.sig));
  } else {
    return fmt::format("FullPk[hash: {}, sig: {}, hashes: {{{}, ..., {}}}]",
                       array_first_last(pk->hash),
                       array_first_last(pk->sig.sig),
                       array_first_last(pk->hashes.front()),
                       array_first_last(pk->hashes.back()));
  }
}

}  // namespace dory::pony::logging

namespace dory::pony {
template <typename Duration>
static void busy_sleep(Duration duration) {
  auto const start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < duration)
    ;
}
}  // namespace dory::pony

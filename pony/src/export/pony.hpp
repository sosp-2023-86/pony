#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

#include "config.hpp"
#include "types.hpp"

namespace dory::pony {
class Pony;

class PonyLib {
 public:
  PonyLib(ProcId id, bool caching = true);

  void sign(Signature &sig, uint8_t const *m, size_t mlen);

  bool verify(Signature const &sig, uint8_t const *m, size_t mlen, ProcId pid);
  std::optional<bool> tryFastVerify(Signature const &sig, uint8_t const *m,
                                    size_t mlen, ProcId pid);
  bool slowVerify(Signature const &sig, uint8_t const *m, size_t mlen,
                  ProcId pid);

  void enableSlowPath(bool enable);

  bool replenishedSks(size_t replenished = SkCtxs);

  bool replenishedPks(ProcId pid, size_t replenished = SkCtxs);

 private:
  struct PonyDeleter {
    void operator()(Pony *) const;
  };
  std::unique_ptr<Pony, PonyDeleter> impl;
};
}  // namespace dory::pony

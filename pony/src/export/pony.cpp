
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>

#include "../pony.hpp"
#include "pony.hpp"

namespace dory::pony {
__attribute__((visibility("default"))) void PonyLib::PonyDeleter::operator()(
    Pony *ptr) const {
  delete ptr;
}

__attribute__((visibility("default"))) PonyLib::PonyLib(ProcId id, bool caching)
    : impl{std::unique_ptr<Pony, PonyDeleter>(new Pony(id, caching),
                                              PonyDeleter())} {}

__attribute__((visibility("default"))) void PonyLib::sign(Signature &sig,
                                                          uint8_t const *m,
                                                          size_t mlen) {
  impl->sign(sig, m, mlen);
}

__attribute__((visibility("default"))) bool PonyLib::verify(
    Signature const &sig, uint8_t const *m, size_t mlen, ProcId pid) {
  return impl->verify(sig, m, mlen, pid);
}

__attribute__((visibility("default"))) std::optional<bool>
PonyLib::tryFastVerify(Signature const &sig, uint8_t const *m, size_t mlen,
                       ProcId pid) {
  return impl->try_fast_verify(sig, m, mlen, pid);
}

__attribute__((visibility("default"))) bool PonyLib::slowVerify(
    Signature const &sig, uint8_t const *m, size_t mlen, ProcId pid) {
  return impl->slow_verify(sig, m, mlen, pid);
}

__attribute__((visibility("default"))) void PonyLib::enableSlowPath(
    bool const enable) {
  impl->enable_slow_path(enable);
}

__attribute__((visibility("default"))) bool PonyLib::replenishedSks(
    size_t replenished) {
  return impl->replenished_sks(replenished);
}

__attribute__((visibility("default"))) bool PonyLib::replenishedPks(
    ProcId const pid, size_t replenished) {
  return impl->replenished_pks(pid, replenished);
}

}  // namespace dory::pony

#pragma once

#include <cstddef>
#include <cstring>
#include <deque>
#include <unordered_map>

#include <xxhash.h>

#include <dory/shared/logger.hpp>

#include "hors.hpp"
#include "types.hpp"

namespace dory::pony {
class SignatureCache {
 public:
  SignatureCache(bool bypass = false, size_t length = 1024)
      : bypass{bypass},
        length{length},
        good_sigs{length},
        recently_added{length},
        LOGGER_INIT(logger, "Pony::SignatureCache") {
    LOGGER_TRACE(logger, "Cache is configured to bypass? {}", bypass);
  }

  void storeVerifiedSignature(Signature const &sig, HorsHash const &hash) {
    if (bypass) {
      return;
    }

    auto key = hash_code(sig);
    auto it = good_sigs.find(key);

    if (it != good_sigs.end() && identical({sig, hash}, it->second)) {
      // it->second = {sig, hash};
      return;
    }

    if (good_sigs.size() > length) {
      auto key = recently_added.back();
      recently_added.pop_back();
      good_sigs.erase(key);
    }

    good_sigs.insert({key, {sig, hash}});

    recently_added.push_front(key);
  }

  bool verifiedSignatureExists(Signature const &sig, HorsHash const &hash) {
    if (bypass) {
      return false;
    }

    auto key = hash_code(sig);
    auto it = good_sigs.find(key);

    if (it == good_sigs.end() || !identical({sig, hash}, it->second)) {
      return false;
    }

    return true;
  }

 private:
  bool bypass;
  size_t length;

  using Key = uint64_t;
  using Value = std::pair<Signature, HorsHash>;
  std::unordered_map<Key, Value> good_sigs;

  // Add to front, remove from back
  std::deque<Key> recently_added;

  LOGGER_DECL(logger);

  Key hash_code(Signature const &sig) {
    return XXH3_64bits(reinterpret_cast<uint8_t const *>(&sig), sizeof(sig));
  }

  bool identical(Value const &a, Value const &b) {
    return (std::memcmp(&(a.first), &(b.first), sizeof(Signature)) == 0) &&
           (std::memcmp(&(a.second), &(b.second), sizeof(HorsHash)) == 0);
  }
};
}  // namespace dory::pony

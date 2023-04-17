#pragma once

#include <cstddef>
#include <cstring>
#include <deque>
#include <unordered_map>

#include <xxhash.h>

#include "../types.hpp"

namespace dory::pony {
class EddsaCache {
 public:
  EddsaCache(size_t length = SkCtxs / EddsaBatchSize)
      : length{length}, good_sigs{length}, recently_added{length} {}

  void store(BatchedEddsaSignature const &sig) {
    auto const key = hash_code(sig);
    auto const it = good_sigs.find(key);

    if (it != good_sigs.end() && sig == it->second) {
      return;
    }

    if (good_sigs.size() > length) {
      auto const key = recently_added.back();
      recently_added.pop_back();
      good_sigs.erase(key);
    }

    good_sigs.try_emplace(key, sig);

    recently_added.push_front(key);
  }

  bool contains(BatchedEddsaSignature const &sig) {
    auto const key = hash_code(sig);
    auto const it = good_sigs.find(key);

    if (it == good_sigs.end() || sig != it->second) {
      return false;
    }

    return true;
  }

 private:
  bool bypass;
  size_t length;

  using Key = uint64_t;
  using Value = BatchedEddsaSignature;
  std::unordered_map<Key, Value> good_sigs;

  // Add to front, remove from back
  std::deque<Key> recently_added;

  Key hash_code(Value const &sig) {
    return XXH3_64bits(reinterpret_cast<uint8_t const *>(&sig), sizeof(sig));
  }
};
}  // namespace dory::pony

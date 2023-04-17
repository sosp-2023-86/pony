#include <fmt/core.h>
#include <fstream>
#include <iostream>

#include <dory/shared/branching.hpp>

#include "common.hpp"

using namespace dory::ubft;

using namespace pony;

int main() {
  std::ifstream random("/dev/random", std::ios::in | std::ios::binary);
  if (!random) {
    exit(1);
  }
  auto private_key = std::make_unique<horse::PrivateKey>(random);
  auto public_key = std::make_unique<horse::PublicKey>(*private_key);

  fmt::print("Private key size: {}B (t={}, d={})\n", sizeof(*private_key),
             horse::t, horse::d);
  fmt::print("Public key size: {}B\n", sizeof(*public_key));
  fmt::print("Signature size: {}B ({} secrets)\n", sizeof(horse::Signature),
             horse::secrets_per_signature);
  std::vector<uint8_t> message = {0xC0, 0xCA, 0xC0, 0x1A};

  auto const sign_start = std::chrono::steady_clock::now();
  size_t const to_sign = 100000;
  for (size_t i = 0; i < to_sign; i++) {
    auto const signature =
        private_key->sign(message.data(), message.data() + message.size());
    auto const good = public_key->verify(
        message.data(), message.data() + message.size(), signature);
    if (unlikely(!good)) {
      fmt::print("FAILURE!\n");
    }
  }
  fmt::print("Signed and verified in {}.\n",
             (std::chrono::steady_clock::now() - sign_start) / to_sign);

  // fmt::print("Signature: {}\n", signature);
  // auto const verify_start = std::chrono::steady_clock::now();
  // auto const valid = public_key.verify(message.data(), message.data() +
  // message.size(), signature); fmt::print("Verified ({}) in {}.\n", valid,
  // std::chrono::steady_clock::now() - verify_start);
  return 0;
}

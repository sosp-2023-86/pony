#include <cstddef>
#include <stdexcept>

#include "../config.hpp"
#include "check.hpp"

namespace dory::pony::sanity {
// These should be filled by the preprocessor during compilation
extern int Scheme;
extern size_t HorsLogSecretsPerSecretKey;
extern size_t HorsSecretsPerSignature;
extern size_t HorsSignaturesPerSecretKey;
extern size_t HorsPkEmbedding;
extern size_t HorsLogNbRoots;
extern size_t WotsLogSecretsDepth;
extern bool WotsVerifyOnGpu;
extern bool PresendEddsaOnly;

void check() {
  if (HorsLogSecretsPerSecretKey != HORS_LOG_SECRETS_PER_SECRET_KEY) {
    throw std::logic_error(
        "Mismatch of compile-time config vs run-time config of header files");
  }

  if (HorsSecretsPerSignature != HORS_SECRETS_PER_SIGNATURE) {
    throw std::logic_error(
        "Mismatch of compile-time config vs run-time config of header files");
  }

  if (HorsSignaturesPerSecretKey != HORS_SIGNATURES_PER_SECRET_KEY) {
    throw std::logic_error(
        "Mismatch of compile-time config vs run-time config of header files");
  }

  if (HorsPkEmbedding != HORS_PK_EMBEDDING) {
    throw std::logic_error(
        "Mismatch of compile-time config vs run-time config of header files");
  }

  if (HorsLogNbRoots != HORS_LOG_NB_ROOTS) {
    throw std::logic_error(
        "Mismatch of compile-time config vs run-time config of header files");
  }

  if (WotsLogSecretsDepth != WOTS_LOG_SECRETS_DEPTH) {
    throw std::logic_error(
        "Mismatch of compile-time config vs run-time config of header files");
  }

  if (WotsVerifyOnGpu != WOTS_VERIFY_ON_GPU) {
    throw std::logic_error(
        "Mismatch of compile-time config vs run-time config of header files");
  }

  if (PresendEddsaOnly != PRESEND_EDDSA_ONLY) {
    throw std::logic_error(
        "Mismatch of compile-time config vs run-time config of header files");
  }
}
}  // namespace dory::pony::sanity

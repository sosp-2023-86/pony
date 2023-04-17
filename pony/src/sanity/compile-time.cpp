#include <cstddef>

namespace dory::pony::sanity {
// These should be filled by the preprocessor during compilation
// IMPORTANT: Also edit `run-time.cpp`

int Scheme = SCHEME;
size_t HorsLogSecretsPerSecretKey = HORS_LOG_SECRETS_PER_SECRET_KEY;
size_t HorsSecretsPerSignature = HORS_SECRETS_PER_SIGNATURE;
size_t HorsSignaturesPerSecretKey = HORS_SIGNATURES_PER_SECRET_KEY;
size_t HorsPkEmbedding = HORS_PK_EMBEDDING;
size_t HorsLogNbRoots = HORS_LOG_NB_ROOTS;
size_t WotsLogSecretsDepth = WOTS_LOG_SECRETS_DEPTH;
bool WotsVerifyOnGpu = WOTS_VERIFY_ON_GPU;
bool PresendEddsaOnly = PRESEND_EDDSA_ONLY;
}  // namespace dory::pony::sanity

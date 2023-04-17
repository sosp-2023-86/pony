#pragma once

#include <array>
#include <cstddef>

// #include <dory/shared/cx-math.hpp>

// Non-standard directive, but both gcc and clang provide it
#if defined __has_include
#if __has_include("internal/compile-time-config.hpp")
#include "internal/compile-time-config.hpp"
#endif
#else
#warning "Cannot export as a shared library"
#endif

#ifndef SCHEME
#error "Define SCHEME"
#endif

#ifndef HORS_LOG_SECRETS_PER_SECRET_KEY
#error "Define HORS_LOG_SECRETS_PER_SECRET_KEY"
#endif

#ifndef HORS_SECRETS_PER_SIGNATURE
#error "Define HORS_SECRETS_PER_SIGNATURE"
#endif

#ifndef HORS_SIGNATURES_PER_SECRET_KEY
#error "Define HORS_SIGNATURES_PER_SECRET_KEY"
#endif

#ifndef HORS_PK_EMBEDDING
#error "Define HORS_PK_EMBEDDING"
#endif

#ifndef HORS_LOG_NB_ROOTS
#error "Define HORS_LOG_NB_ROOTS"
#endif

#ifndef WOTS_LOG_SECRETS_DEPTH
#error "Define WOTS_LOG_SECRETS_DEPTH"
#endif

#ifndef WOTS_VERIFY_ON_GPU
#error "Define WOTS_VERIFY_ON_GPU"
#endif

#ifndef PRESEND_EDDSA_ONLY
#error "Define PRESEND_EDDSA_ONLY"
#endif

#define static_assert_scheme(scheme, x) static_assert(Scheme != (scheme) || (x))
#define static_assert_hors(x) static_assert_scheme(HORS, x)
#define static_assert_wots(x) static_assert_scheme(WOTS, x)

namespace dory::pony {

enum Schemes { HORS = 0, WOTS = 1 };
size_t constexpr Scheme = SCHEME;

namespace hors {
size_t constexpr LogSecretsPerSecretKey = HORS_LOG_SECRETS_PER_SECRET_KEY;

enum PkEmbeddings { Full = 0, Merkle = 1, None = 2 };
// Merkle Proofs
PkEmbeddings constexpr PkEmbedding =
    static_cast<PkEmbeddings>(HORS_PK_EMBEDDING);
// Having LogNbRoots = ceil(log2(SecretsPerSignature)) should provide optimal
// compression. We cannot use LogSignaturesPerSecretKey because it is a fp.
size_t constexpr LogNbRoots = HORS_LOG_NB_ROOTS;
size_t constexpr NbRoots = 1 << LogNbRoots;

// Removed because it bottoms out the complier recursion
// long double constexpr LogSecretsPerSignature =
//     cx::log2(static_cast<long double>(HORS_SECRETS_PER_SIGNATURE));
// long double constexpr LogSignaturesPerSecretKey =
//     cx::log2(static_cast<long double>(HORS_SIGNATURES_PER_SECRET_KEY));
// long double constexpr SecurityLevel =
//     static_cast<long double>(HORS_SECRETS_PER_SIGNATURE) *
//     (static_cast<long double>(LogSecretsPerSecretKey) -
//     LogSecretsPerSignature -
//      LogSignaturesPerSecretKey);
}  // namespace hors

namespace wots {
size_t constexpr LogSecretsDepth = WOTS_LOG_SECRETS_DEPTH;
size_t constexpr SecretsDepth = 1 << LogSecretsDepth;

std::array<size_t, 9> constexpr PrecomputedL1 = {0,  128, 64, 43, 32,
                                                 26, 21,  18, 16};
std::array<size_t, 9> constexpr PrecomputedL2 = {0, 7, 3, 2, 2, 1, 1, 1, 1};
size_t constexpr L1 = PrecomputedL1[LogSecretsDepth];
size_t constexpr L2 = PrecomputedL2[LogSecretsDepth];

size_t constexpr L = L1 + L2;

bool constexpr VerifyOnGpu = WOTS_VERIFY_ON_GPU;

// long double constexpr SecurityLevel = -1;
}  // namespace wots

size_t constexpr SecretsPerSecretKey =
    Scheme == HORS ? (1 << hors::LogSecretsPerSecretKey) : wots::L;

size_t constexpr SecretsPerSignature =
    Scheme == HORS ? HORS_SECRETS_PER_SIGNATURE : wots::L;

size_t constexpr SignaturesPerSecretKey =
    Scheme == HORS ? HORS_SIGNATURES_PER_SECRET_KEY : 1;

size_t constexpr SecretsDepth = Scheme == HORS ? 1 : wots::SecretsDepth;

size_t constexpr SkCtxs =
    (SecretsPerSignature == 8 ? 15 : 127) / SignaturesPerSecretKey + 1;

// long double constexpr SecurityLevel =
//     Scheme == HORS ? hors::SecurityLevel : wots::SecurityLevel;

// LogNbRoots should only be specified if we use merkle proofs.
static_assert_hors(hors::LogNbRoots == 0 || hors::PkEmbedding == hors::Merkle);
static_assert_hors(hors::PkEmbedding != hors::Merkle ||
                   (hors::NbRoots >= SecretsPerSignature &&
                    SecretsPerSignature > hors::NbRoots / 2));
// Given the nonce, it's enough to use only 128 bits of entropy provided by the
// hash
static_assert_hors(SecretsPerSignature* hors::LogSecretsPerSecretKey >= 128);

// One secret should be revealed for each secret in the SK.
static_assert_wots(SecretsPerSignature == SecretsPerSecretKey);
// The WotsLogSecretsDepth should be greater than 0 in WOTS.
static_assert_wots(wots::LogSecretsDepth > 0);
// In the case of WOTS, the SKs should only be used once.
static_assert_wots(SignaturesPerSecretKey == 1);

bool constexpr PresendEddsaOnly = PRESEND_EDDSA_ONLY;
// PresendEddsaOnly in HORS is only compatible with fully-embedded pks.
static_assert_hors(!PresendEddsaOnly || hors::PkEmbedding == hors::Full);
// PresendEddsaOnly in WOTS is incompatible with on-GPU verification.
static_assert_wots(!(PresendEddsaOnly && wots::VerifyOnGpu));

size_t constexpr EddsaBatchSize = 16;
}  // namespace dory::pony

#if defined __has_include
#if __has_include("internal/compile-time-config.hpp")
// Clear the preprocessor namespace
#undef HORS_LOG_SECRETS_PER_SECRET_KEY
#undef HORS_SECRETS_PER_SIGNATURE
#undef HORS_SIGNATURES_PER_SECRET_KEY
#undef HORS_PK_EMBEDDING
#undef HORS_LOG_NB_ROOTS
#undef WOTS_LOG_SECRETS_DEPTH
#undef WOTS_VERIFY_ON_GPU
#undef PRESEND_EDDSA_ONLY
#endif
#endif

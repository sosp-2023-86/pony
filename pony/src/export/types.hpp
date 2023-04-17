#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include "config.hpp"

namespace dory::pony {

using ProcId = int;
using Seed = std::array<uint8_t, 32>;

using EddsaSignature = std::array<uint8_t, 64>;

using Hash = std::array<uint8_t, 32>;
using Secret = Hash;

struct BatchedEddsaSignature {
  std::array<Hash, EddsaBatchSize> hashes;
  EddsaSignature sig;

  bool includes(Hash const& hash) const {
    for (auto const& other : hashes) {
      if (other == hash) {
        return true;
      }
    }
    return false;
  }

  bool operator==(BatchedEddsaSignature const& o) const {
    static_assert(sizeof(hashes) == EddsaBatchSize * sizeof(Hash));
    return std::memcmp(&hashes, &o.hashes, sizeof(hashes)) == 0 && sig == o.sig;
  }

  bool operator!=(BatchedEddsaSignature const& o) const {
    return !(*this == o);
  }
};

struct PublicKey {
  // if Signature == HorsMerkleSignature: hash = H(roots)
  // else: hash = H(hashes)
  Hash hash;
  BatchedEddsaSignature sig;
  std::array<Hash, SecretsPerSecretKey> hashes;
};

static size_t constexpr SentPkPrefix =
    PresendEddsaOnly ? offsetof(PublicKey, hashes) : sizeof(PublicKey);

// HORS
// Signatures with the full PK embeded.
struct HorsFullSignature {
  Hash pk_hash;  // To find the PK. Should match the hashes.
  BatchedEddsaSignature pk_sig;

  Hash nonce;                                                // Prevents CMA.
  std::array<Hash, SecretsPerSecretKey> secrets_and_hashes;  // Interleaved mix

  enum Validity {
    Valid,
    InvalidPkHash,
    InvalidPkSig,
    InvalidNonce,
    InvalidSecret
  };

  std::array<Validity, 3> static constexpr InvalidFast = {
      InvalidPkSig, InvalidNonce, InvalidSecret};
  std::array<Validity, 1> static constexpr InvalidSlow = {InvalidPkHash};

  static char const* to_string(Validity const validity) {
    switch (validity) {
      case Valid:
        return "VALID";
      case InvalidPkHash:
        return "INVALID_PK_HASH";
      case InvalidPkSig:
        return "INVALID_PK_SIG";
      case InvalidNonce:
        return "INVALID_NONCE";
      case InvalidSecret:
        return "INVALID_SECRET";
      default:
        return "UNKNOWN";
    }
  }

  HorsFullSignature const& data() const noexcept { return *this; }

  bool operator==(const HorsFullSignature& other) const {
    return std::memcmp(this, &other, sizeof(HorsFullSignature)) == 0;
  }
};

// Signatures with merkle proofs.
using Roots = std::array<Hash, hors::NbRoots>;

// Note: does not include the root
struct MerkleProof {
  size_t static constexpr Length =
      hors::LogSecretsPerSecretKey - hors::LogNbRoots;
  // Hash leaf; No need for the leaf as it is simply the hash of the secret.
  // size_t leaf_index; No need for the index as this is given by HorsHash.
  std::array<Hash, Length> path;
};

struct SecretAndProof {
  Secret secret;
  MerkleProof proof;
};

struct HorsMerkleSignature {
  Hash pk_hash;  // To find the PK. Should match the roots.
  BatchedEddsaSignature pk_sig;

  Hash nonce;  // Prevents CMA.
  Roots roots;
  std::array<SecretAndProof, SecretsPerSignature> secrets;

  enum Validity {
    Valid,
    InvalidPkHash,
    InvalidPkSig,
    InvalidNonce,
    InvalidRoots,
    InvalidSecret,
    InvalidMerkleProof
  };

  std::array<Validity, 5> static constexpr InvalidFast = {
      InvalidPkSig, InvalidNonce, InvalidRoots, InvalidSecret,
      InvalidMerkleProof};
  std::array<Validity, 1> static constexpr InvalidSlow = {InvalidPkHash};

  static char const* to_string(Validity const validity) {
    switch (validity) {
      case Valid:
        return "VALID";
      case InvalidPkHash:
        return "INVALID_PK_HASH";
      case InvalidPkSig:
        return "INVALID_PK_SIG";
      case InvalidNonce:
        return "INVALID_NONCE";
      case InvalidRoots:
        return "INVALID_ROOTS";
      case InvalidSecret:
        return "INVALID_SECRET";
      case InvalidMerkleProof:
        return "INVALID_MERKLE_PROOF";
      default:
        return "UNKNOWN";
    }
  }

  HorsMerkleSignature const& data() const noexcept { return *this; }

  bool operator==(const HorsMerkleSignature& other) const {
    return std::memcmp(this, &other, sizeof(HorsMerkleSignature)) == 0;
  }
};

struct HorsSyncSignature {
  Hash pk_hash;  // To find the PK. Should match the hashes.

  Hash nonce;  // Prevents CMA.
  std::array<Hash, SecretsPerSignature> secrets;

  enum Validity {
    Valid,
    InvalidPkHash,
    InvalidPkSig,
    InvalidNonce,
    InvalidSecret
  };

  std::array<Validity, 2> static constexpr InvalidFast = {InvalidNonce,
                                                          InvalidSecret};
  std::array<Validity, 0> static constexpr InvalidSlow = {};

  static char const* to_string(Validity const validity) {
    switch (validity) {
      case Valid:
        return "VALID";
      case InvalidNonce:
        return "INVALID_NONCE";
      case InvalidSecret:
        return "INVALID_SECRET";
      default:
        return "UNKNOWN";
    }
  }

  HorsSyncSignature const& data() const noexcept { return *this; }

  bool operator==(const HorsSyncSignature& other) const {
    return std::memcmp(this, &other, sizeof(HorsSyncSignature)) == 0;
  }
};

// WOTS+
struct WotsSignature {
  Hash pk_hash;  // To find the PK. Should match the hashes.
  BatchedEddsaSignature pk_sig;

  Hash nonce;  // Prevents CMA.
  std::array<Hash, SecretsPerSignature> secrets;

  enum Validity {
    Valid,
    InvalidPkHash,
    InvalidPkSig,
    InvalidNonce,
    InvalidSecret
  };

  std::array<Validity, 3> static constexpr InvalidFast = {
      InvalidPkSig, InvalidNonce, InvalidSecret};
  std::array<Validity, 1> static constexpr InvalidSlow = {InvalidPkHash};

  static char const* to_string(Validity const validity) {
    switch (validity) {
      case Valid:
        return "VALID";
      case InvalidPkHash:
        return "INVALID_PK_HASH";
      case InvalidPkSig:
        return "INVALID_PK_SIG";
      case InvalidNonce:
        return "INVALID_NONCE";
      case InvalidSecret:
        return "INVALID_SECRET";
      default:
        return "UNKNOWN";
    }
  }

  WotsSignature const& data() const noexcept { return *this; }

  bool operator==(const WotsSignature& other) const {
    return std::memcmp(this, &other, sizeof(WotsSignature)) == 0;
  }
};

using Signature = std::conditional_t<
    Scheme == WOTS, WotsSignature,
    std::conditional_t<
        hors::PkEmbedding == hors::Merkle, HorsMerkleSignature,
        std::conditional_t<hors::PkEmbedding == hors::Full, HorsFullSignature,
                           HorsSyncSignature>>>;
}  // namespace dory::pony

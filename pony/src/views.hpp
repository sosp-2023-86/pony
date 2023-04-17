#pragma once

#include <array>
#include <cstring>
#include <type_traits>

#include <fmt/core.h>
#include <fmt/ranges.h>

#include <hipony/enumerate.hpp>

#include <dory/crypto/hash/blake3.hpp>
#include <dory/shared/branching.hpp>
#include <dory/shared/logger.hpp>

#include "cache.hpp"
#include "config.hpp"
#include "hors.hpp"
#include "pk/offload.hpp"
#include "sk/offload.hpp"
#include "types.hpp"
#include "wots.hpp"

namespace dory::pony {

class MtView {
  using Leaves = std::array<crypto::hash::Blake3Hash, SecretsPerSecretKey>;
  using Nodes = std::array<crypto::hash::Blake3Hash, SecretsPerSecretKey - 1>;

 public:
  MtView(PkOffload& offload)
      : nodes{*reinterpret_cast<Nodes*>(
            offload.memoryWindow(PkOffload::MT, PkOffload::Host).p)},
        leaves{reinterpret_cast<PublicKey*>(
                   offload.memoryWindow(PkOffload::PK, PkOffload::Host).p)
                   ->hashes} {}

  MtView(SkOffload& offload)
      : nodes{*reinterpret_cast<Nodes*>(
            offload.memoryWindow(SkOffload::MT, SkOffload::Host).p)},
        leaves{reinterpret_cast<PublicKey*>(
                   offload.memoryWindow(SkOffload::PK, SkOffload::Host).p)
                   ->hashes} {}

  MerkleProof prove(size_t leaf_index) const {
    if (leaf_index >= leaves.size()) {
      throw std::runtime_error(fmt::format("Leaf index ({}) >= size ({}).",
                                           leaf_index, leaves.size()));
    }
    MerkleProof proof;
    // proof.leaf = leaf(leaf_index);
    // proof.leaf_index = leaf_index;
    size_t node = rootIndexfor(leaf_index);
    for (size_t i = 0; i < proof.path.size(); i++) {
      auto const leaf_direction =
          (leaf_index >> (proof.path.size() - 1 - i)) & 1;
      auto left_child = (node << 1) + 1;
      auto child_in_path = left_child + (1 - leaf_direction);
      proof.path[i] = child_in_path < nodes.size() ? nodes[child_in_path]
                                                   : leaf(leaf_index ^ 1);
      node = left_child + leaf_direction;
    }
    return proof;
  }

  /**
   * @brief Verify that the path comes from this tree.
   *
   */
  bool verify(MerkleProof const& proof, size_t const leaf_index) const {
    size_t node = rootIndexfor(leaf_index);
    for (size_t i = 0; i < proof.path.size(); i++) {
      auto const leaf_direction =
          (leaf_index >> (proof.path.size() - i - 1)) & 1;
      auto left_child = (node << 1) + 1;
      auto child_in_path = left_child + (1 - leaf_direction);
      auto const& expected_element =
          (child_in_path < nodes.size() ? nodes[child_in_path]
                                        : leaf(leaf_index ^ 1));
      if (unlikely(proof.path[i] != expected_element)) {
        LOGGER_WARN(logger, "Invalid path element #{}: {} vs {}", i,
                    proof.path[i], expected_element);
        return false;
      }

      node = left_child + leaf_direction;
    }
    // return leaf(proof.leaf_index) == proof.leaf;
    return true;
  }

  Roots const& getRoots() const {
    return *reinterpret_cast<Roots const*>(&nodes[hors::NbRoots - 1]);
  }

  bool inline hasRoots(Roots const& roots) const {
    // We statically assert the packing of the array.
    static_assert(sizeof(Roots) == hors::NbRoots * sizeof(Roots::value_type));
    return std::memcmp(&roots, &getRoots(), sizeof(roots)) == 0;
  }

  size_t rootIndexfor(size_t const leaf_index) const {
    size_t const first_root_index = hors::NbRoots - 1;
    size_t const root_offset = leaf_index >> MerkleProof::Length;
    return first_root_index + root_offset;
  }

 private:
  Hash const& leaf(size_t const index) const { return leaves[index]; }

  Nodes const& nodes;
  Leaves const& leaves;
  LOGGER_DECL_INIT(logger, "Pony::MtView");
};

class PkView {
  using Hashes = std::array<crypto::hash::Blake3Hash, SecretsPerSecretKey>;

 public:
  PkView(PkOffload& offload)
      : hashes{reinterpret_cast<PublicKey*>(
                   offload.memoryWindow(PkOffload::PK, PkOffload::Host).p)
                   ->hashes},
        hash{reinterpret_cast<PublicKey*>(
                 offload.memoryWindow(PkOffload::PK, PkOffload::Host).p)
                 ->hash},
        sig{reinterpret_cast<PublicKey*>(
                offload.memoryWindow(PkOffload::PK, PkOffload::Host).p)
                ->sig},
        mt{offload} {}

  PkView(SkOffload& offload)
      : hashes{reinterpret_cast<PublicKey*>(
                   offload.memoryWindow(SkOffload::PK, SkOffload::Host).p)
                   ->hashes},
        hash{reinterpret_cast<PublicKey*>(
                 offload.memoryWindow(SkOffload::PK, SkOffload::Host).p)
                 ->hash},
        sig{reinterpret_cast<PublicKey*>(
                offload.memoryWindow(SkOffload::PK, SkOffload::Host).p)
                ->sig},
        mt{offload} {}

  MtView const& getMt() const { return mt; }

  /**
   * @brief Verify if a signature is valid.
   *
   */
  bool verify(WotsSignature const& sig, uint8_t const* msg,
              size_t const msg_len, SignatureCache& cache,
              PkOffload* const offload) const {
    // Note: useless to check sig.pk_hash as this is how this pk was found.

    if (getSig() != sig.pk_sig) {
      LOGGER_WARN(logger, "Pk sig does not match: {} vs {}!", sig.pk_sig.sig,
                  getSig().sig);
      return false;
    }

    if (wots::VerifyOnGpu && offload) {
      if (!offload->verify(sig, msg, msg_len)) {
        LOGGER_WARN(logger, "Invalid secrets according to GPU!");
        return false;
      }
    } else {
      if (!verifySecrets(sig, msg, msg + msg_len, cache)) {
        LOGGER_WARN(logger, "Invalid secrets!");
        return false;
      }
    }

    return true;
  }

  /**
   * @brief Verify if a signature is valid.
   *
   */
  bool verify(HorsMerkleSignature const& sig, uint8_t const* msg,
              size_t const msg_len, SignatureCache& cache,
              PkOffload const*) const {
    // Note: useless to check sig.pk_hash as this is how this pk was found.

    if (!mt.hasRoots(sig.roots)) {
      LOGGER_WARN(logger, "Invalid roots: {} vs {}!", mt.getRoots(), sig.roots);
      return false;
    }

    if (getSig() != sig.pk_sig) {
      LOGGER_WARN(logger, "Invalid roots sig: {} vs {}!", sig.pk_sig.sig,
                  getSig().sig);
      return false;
    }

    if (!verifySecrets(sig, msg, msg + msg_len, cache)) {
      LOGGER_WARN(logger, "Invalid secrets!");
      return false;
    }

    return true;
  }

  bool verify(HorsFullSignature const& sig, uint8_t const* msg,
              size_t const msg_len, SignatureCache& cache,
              PkOffload const*) const {
    // Note: useless to check sig.pk_hash as this is how this pk was found.

    if (getSig() != sig.pk_sig) {
      LOGGER_WARN(logger, "Pk sig does not match: {} vs {}!", sig.pk_sig.sig,
                  getSig().sig);
      return false;
    }

    if (!verifySecrets(sig, msg, msg + msg_len, cache)) {
      LOGGER_WARN(logger, "Invalid secrets!");
      return false;
    }

    return true;
  }

  bool verify(HorsSyncSignature const& sig, uint8_t const* msg,
              size_t const msg_len, SignatureCache& cache,
              PkOffload const*) const {
    // Note: useless to check sig.pk_hash as this is how this pk was found.

    if (!verifySecrets(sig, msg, msg + msg_len, cache)) {
      LOGGER_WARN(logger, "Invalid secrets!");
      return false;
    }

    return true;
  }

  bool associatedTo(Signature const& sig) const { return sig.pk_hash == hash; }

  Hash const& getHash() const { return hash; }
  Hash& getHash() { return hash; }

  BatchedEddsaSignature const& getSig() const { return sig; }
  BatchedEddsaSignature& getSig() { return sig; }

  Hashes const& getHashes() const { return hashes; }

 private:
  bool verifySecrets(WotsSignature const& sig, uint8_t const* const begin,
                     uint8_t const* const end, SignatureCache& cache) const {
    auto sig_hashes = sig.secrets;

    WotsHash h(hash, sig.nonce, begin, end);
    // if (cache.verifiedSignatureExists(sig, h)) {
    //   return true;
    // }

    for (size_t secret = 0; secret < SecretsPerSignature; secret++) {
      auto const depth = h.getSecretDepth(secret);
      auto const to_hash = SecretsDepth - depth - 1;
      for (size_t i = 0; i < to_hash; i++) {
        sig_hashes[secret] = crypto::hash::blake3(sig_hashes[secret]);
      }
    }

    // cache.storeVerifiedSignature(sig, h);
    if constexpr (PresendEddsaOnly) {
      return crypto::hash::blake3(sig_hashes) == hash;
    } else {
      return std::memcmp(&sig_hashes, &hashes, sizeof(hashes)) == 0;
    }
  }

  bool verifySecrets(HorsMerkleSignature const& sig, uint8_t const* const begin,
                     uint8_t const* const end, SignatureCache& cache) const {
    HorsHash h(hash, sig.nonce, begin, end);
    // if (cache.verifiedSignatureExists(sig, h)) {
    //   return true;
    // }

    for (size_t hash_offset = 0, i = 0; i < SecretsPerSignature;
         i++, hash_offset += hors::LogSecretsPerSecretKey) {
      auto const secret_index = h.getSecretIndex(hash_offset);

      if (crypto::hash::blake3(sig.secrets[i].secret) != hashes[secret_index]) {
        LOGGER_WARN(logger, "Invalid secret #{} @{} hash: {} vs {}", i,
                    secret_index, crypto::hash::blake3(sig.secrets[i].secret),
                    hashes[secret_index]);
        return false;
      }

      if (!mt.verify(sig.secrets[i].proof, secret_index)) {
        LOGGER_WARN(logger, "Invalid merkle proof #{}", i);
        return false;
      }
    }

    // cache.storeVerifiedSignature(sig, h);
    return true;
  }

  bool verifySecrets(HorsFullSignature const& sig, uint8_t const* const begin,
                     uint8_t const* const end, SignatureCache& cache) const {
    auto sig_hashes = sig.secrets_and_hashes;

    HorsHash h(hash, sig.nonce, begin, end);
    // if (cache.verifiedSignatureExists(sig, h)) {
    //   return true;
    // }

    for (size_t hash_offset = 0, i = 0; i < SecretsPerSignature;
         i++, hash_offset += hors::LogSecretsPerSecretKey) {
      auto const secret_index = h.getSecretIndex(hash_offset);

      sig_hashes[secret_index] =
          crypto::hash::blake3(sig.secrets_and_hashes[secret_index]);
    }

    // cache.storeVerifiedSignature(sig, h);

    if constexpr (PresendEddsaOnly) {
      return crypto::hash::blake3(sig_hashes) == hash;
    } else {
      return std::memcmp(&sig_hashes, &hashes, sizeof(hashes)) == 0;
    }
  }

  bool verifySecrets(HorsSyncSignature const& sig, uint8_t const* const begin,
                     uint8_t const* const end, SignatureCache& cache) const {
    HorsHash h(hash, sig.nonce, begin, end);
    // if (cache.verifiedSignatureExists(sig, h)) {
    //   return true;
    // }

    for (size_t hash_offset = 0, i = 0; i < SecretsPerSignature;
         i++, hash_offset += hors::LogSecretsPerSecretKey) {
      auto const secret_index = h.getSecretIndex(hash_offset);

      if (crypto::hash::blake3(sig.secrets[i]) != hashes[secret_index]) {
        LOGGER_WARN(logger, "Invalid secret #{} @{} hash: {} vs {}", i,
                    secret_index, crypto::hash::blake3(sig.secrets[i]),
                    hashes[secret_index]);
        return false;
      }
    }

    // cache.storeVerifiedSignature(sig, h);
    return true;
  }

  Hashes const& hashes;
  Hash& hash;
  BatchedEddsaSignature& sig;

  MtView const mt;
  LOGGER_DECL_INIT(logger, "Pony::PkView");
};

class SkView {
  using Secrets =
      std::array<std::array<crypto::hash::Blake3Hash, SecretsPerSecretKey>,
                 SecretsDepth>;

 public:
  SkView(SkOffload& offload)
      : secrets{*reinterpret_cast<Secrets*>(
            offload.memoryWindow(SkOffload::SK, SkOffload::Host).p)},
        pk{offload} {}

  template <std::enable_if_t<std::is_same_v<Signature, HorsMerkleSignature>,
                             bool> = true>
  HorsMerkleSignature sign(Hash const& nonce, uint8_t const* msg,
                           size_t const msg_len, SignatureCache& cache) const {
    HorsMerkleSignature sig;
    sig.pk_hash = pk.getHash();
    sig.pk_sig = pk.getSig();
    sig.nonce = nonce;
    sig.roots = pk.getMt().getRoots();

    HorsHash h(pk.getHash(), nonce, msg, msg + msg_len);
    for (size_t hash_offset = 0, secret = 0; secret < SecretsPerSignature;
         secret++, hash_offset += hors::LogSecretsPerSecretKey) {
      auto const secret_index = h.getSecretIndex(hash_offset);
      sig.secrets[secret].secret = secrets.back()[secret_index];
      sig.secrets[secret].proof = pk.getMt().prove(secret_index);
    }

    // cache.storeVerifiedSignature(sig, h);
    return sig;
  }

  template <std::enable_if_t<std::is_same_v<Signature, HorsFullSignature>,
                             bool> = true>
  HorsFullSignature sign(Hash const& nonce, uint8_t const* msg,
                         size_t const msg_len, SignatureCache& cache) const {
    HorsFullSignature sig;
    sig.pk_hash = pk.getHash();
    sig.pk_sig = pk.getSig();
    sig.nonce = nonce;
    sig.secrets_and_hashes = pk.getHashes();

    HorsHash h(pk.getHash(), nonce, msg, msg + msg_len);
    for (size_t hash_offset = 0, secret = 0; secret < SecretsPerSignature;
         secret++, hash_offset += hors::LogSecretsPerSecretKey) {
      auto const secret_index = h.getSecretIndex(hash_offset);
      sig.secrets_and_hashes[secret_index] = secrets.back()[secret_index];
    }

    // cache.storeVerifiedSignature(sig, h);
    return sig;
  }

  template <std::enable_if_t<std::is_same_v<Signature, HorsSyncSignature>,
                             bool> = true>
  HorsSyncSignature sign(Hash const& nonce, uint8_t const* msg,
                         size_t const msg_len, SignatureCache& cache) const {
    HorsSyncSignature sig;
    sig.pk_hash = pk.getHash();
    sig.nonce = nonce;

    HorsHash h(pk.getHash(), nonce, msg, msg + msg_len);
    for (size_t hash_offset = 0, secret = 0; secret < SecretsPerSignature;
         secret++, hash_offset += hors::LogSecretsPerSecretKey) {
      auto const secret_index = h.getSecretIndex(hash_offset);
      sig.secrets[secret] = secrets.back()[secret_index];
    }

    // cache.storeVerifiedSignature(sig, h);
    return sig;
  }

  template <
      std::enable_if_t<std::is_same_v<Signature, WotsSignature>, bool> = true>
  WotsSignature sign(Hash const& nonce, uint8_t const* msg,
                     size_t const msg_len, SignatureCache& cache) const {
    WotsSignature sig;
    sig.pk_hash = pk.getHash();
    sig.pk_sig = pk.getSig();
    sig.nonce = nonce;

    WotsHash h(pk.getHash(), nonce, msg, msg + msg_len);
    for (size_t i = 0; i < SecretsPerSignature; i++) {
      auto const secret_depth = h.getSecretDepth(i);
      sig.secrets[i] = secrets[secret_depth][i];
    }

    // cache.storeVerifiedSignature(sig, h);
    return sig;
  }

  bool associatedTo(Signature const& sig) const { return pk.associatedTo(sig); }

  PkView const& getPk() const { return pk; }

  Hash& getPkHash() { return pk.getHash(); }
  BatchedEddsaSignature& getPkSig() { return pk.getSig(); }

 private:
  Secrets& secrets;

  PkView pk;
  LOGGER_DECL_INIT(logger, "Pony::SkView");
};

}  // namespace dory::pony

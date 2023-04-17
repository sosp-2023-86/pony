#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <vector>

#include <xxhash.h>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <fmt/ranges.h>

#include <dory/crypto/hash/blake3.hpp>
#include <dory/shared/branching.hpp>

#include "../crypto.hpp"
#include "aes-prng.hpp"

namespace dory::ubft::pony {

// A pony signature is:
// mt-roots, EdDSA(mt-roots), secrets, hashes, merkle-proofs

// HORS/pony parameters:
// t - the total # of secrets. The higher, the safer, but the larger the PK is.
//     t = 2 ^ bits_per_secret
// k - the number of secrets revealed in each signature.
//
// The security level of HORS decreases with the number of signatures generated.
// It is equal to k * (log2(t)-log2(k)-log2(#sigs))

size_t constexpr bits_per_secret = 17;
size_t constexpr t = 1 << bits_per_secret;
size_t constexpr log_k = 4;
size_t constexpr k = 1 << log_k;
size_t constexpr secrets_per_signature = k;  // alias

// debug
size_t constexpr log_sigs = 7;
size_t constexpr sigs = 1 << log_sigs;
int64_t constexpr security = k * (bits_per_secret - log_k - log_sigs);

// https://artificial-mind.net/blog/2020/10/31/constexpr-for
#include <type_traits>
/**
 * @brief A template to force for-loop unrolling and increase performance.
 */
template <auto Start, auto End, auto Inc, class F>
constexpr void constexpr_for(F&& f) {
  if constexpr (Start < End) {
    f(std::integral_constant<decltype(Start), Start>());
    constexpr_for<Start + Inc, End, Inc>(f);
  }
}

using Hash = crypto::hash::Blake3Hash;
/**
 * @brief A hash generated from the concatenation of multiple hashes and used to
 *        know which secrets to reveal.
 *
 * A single hash may not be enough to extract k index.
 * We thus need to generate an extended hash (i.e., a combination of multiple
 * hashes).
 */
class ExtendedHash {
 public:
  ExtendedHash(uint8_t const* const begin, uint8_t const* const end) {
    auto const hashes_p = reinterpret_cast<Hash*>(&bytes);
    // If a single hash is needed, we don't prefix it.
    if constexpr (hashes == 1) {
      *hashes_p = crypto::hash::blake3(begin, end);
    } else {
      constexpr_for<0ul, hashes, 1ul>([&hashes_p, &begin, &end](auto const i) {
        auto bs = crypto::hash::blake3_init();
        crypto::hash::blake3_update(bs, i);
        crypto::hash::blake3_update(bs, begin, end);
        *(hashes_p + i) = crypto::hash::blake3_final(bs);
      });
    }
  }

  inline size_t getSecretIndex(size_t const bit_offset) const {
    static size_t constexpr secret_index_mask = t - 1;
    static bool constexpr byte_aligned_secrets = bits_per_secret % 8 == 0;

    // We assume we don't overflow.
    auto const [byte_offset,
                remaining_bit_offset] = [&]() -> std::pair<size_t, size_t> {
      if constexpr (byte_aligned_secrets) {
        // If secrets cover full bytes, we let the compiler know that the
        // remaining bit offset will always be 0 so that it can optimize.
        return {bit_offset / 8ul, 0ul};
      } else {
        auto const div = std::ldiv(bit_offset, 8);
        return {div.quot, div.rem};
      }
    }();

    return (*reinterpret_cast<size_t const*>(&bytes[byte_offset])
            << remaining_bit_offset) &
           secret_index_mask;
  }

 private:
  static size_t constexpr bits = bits_per_secret * secrets_per_signature;
  static size_t constexpr hashes = (bits - 1) / (sizeof(Hash) * 8) + 1;

 public:
  std::array<uint8_t, hashes * sizeof(Hash)> bytes;
};

using Secret = Hash;
using EdDsaCrypto = ubft::Crypto;

/**
 * @brief A forest of merkle trees.
 *
 * An array of `t` hashes is split into `secrets_per_signature` merkle trees.
 *
 * As we will be revealing `k` secrets in each signatures, we optimize by
 * shortening each inclusion proof by using a forest of merkle trees.
 * The root becomes plural (con) but the proofs are shorter (pro).
 */
class MerkleForest {
 public:
  static size_t constexpr nb_trees = secrets_per_signature;
  /**
   * @brief A single tree built from a sub-list of elements.
   *
   */
  class MerkleTree {
   public:
    static size_t constexpr size = t / nb_trees;
    static size_t constexpr height =
        bits_per_secret - log_k + 1;  // = log(size) + 1 = log(t / nb_trees) + 1
                                      // = log(t / k) + 1 = log(t) - log(k) + 1
    static size_t constexpr nb_nodes = (1 << height) - 1;
    static size_t constexpr first_leaf = nb_nodes - size;

    /**
     * @brief A proof of that a leaf belongs to the list of elements.
     *
     * Note: the root is not part of the proof.
     */
    struct Proof {
      static size_t constexpr length =
          height - 1;  // We don't include the root.
      Hash leaf;
      size_t leaf_index;
      std::array<Hash, length> path;

      bool verify(Hash const& root) const {
        auto directions = leaf_index;
        auto acc = leaf;
        for (size_t i = 0; i < Proof::length; i++) {
          auto direction = directions & 1;
          directions >>= 1;
          auto hs = crypto::hash::blake3_init();
          if (direction == 0) {
            crypto::hash::blake3_update(hs, acc);
            crypto::hash::blake3_update(hs, path[path.size() - 1 - i]);
          } else {
            crypto::hash::blake3_update(hs, path[path.size() - 1 - i]);
            crypto::hash::blake3_update(hs, acc);
          }
          acc = crypto::hash::blake3_final(hs);
        }
        return acc == root;
      }
    };

    MerkleTree() = default;  // Uninitialized tree.

    // We implement the = operator to spare the temporary...
    MerkleTree& operator=(std::array<Hash, size> const& elements) {
      // Copy the leaves.
      auto& leaves =
          *reinterpret_cast<std::array<Hash, size>*>(&nodes[first_leaf]);
      leaves = elements;
      // Compute the inner nodes.
      for (size_t right_child = nodes.size() - 1, parent = first_leaf - 1;
           right_child > 0; right_child -= 2, parent--) {
        auto const left_child = right_child - 1;
        // fmt::print("parent {} = hash({} || {})\n", parent, left_child,
        // right_child);
        nodes[parent] = crypto::hash::blake3(nodes[left_child].begin(),
                                             nodes[right_child].end());
      }
      return *this;
    }
    // ... and make the constructor follow the same logic.
    MerkleTree(std::array<Hash, size> const& elements) { *this = elements; }

    Proof prove(size_t leaf_index) const {
      if (leaf_index >= size) {
        throw std::runtime_error(
            fmt::format("Leaf index ({}) >= size ({}).", leaf_index, size));
      }
      Proof proof;
      proof.leaf = nodes[first_leaf + leaf_index];
      proof.leaf_index = leaf_index;
      size_t node = 0;
      for (size_t i = 0; i < Proof::length; i++) {
        auto const leaf_direction = (leaf_index >> (Proof::length - 1 - i)) & 1;
        auto left_child = (node << 1) + 1;
        auto child_in_path = left_child + (1 - leaf_direction);
        proof.path[i] = nodes[child_in_path];
        node = left_child + leaf_direction;
      }
      return proof;
    }

    /**
     * @brief Verify that the path comes from this tree.
     *
     */
    bool verify(Proof const& proof) const {
      size_t node = 0;
      for (size_t i = 0; i < Proof::length; i++) {
        auto const leaf_direction =
            (proof.leaf_index >> (Proof::length - i - 1)) & 1;
        auto left_child = (node << 1) + 1;
        auto child_in_path = left_child + (1 - leaf_direction);
        if (unlikely(nodes[child_in_path] != proof.path[i])) {
          fmt::print("Node #{} ({}) didn't match the {}th proof ({})\n",
                     child_in_path, nodes[child_in_path], i, proof.path[i]);
          return false;
        }
        node = left_child + leaf_direction;
      }
      return nodes[node] == proof.leaf;
    }

    std::array<Hash, nb_nodes> nodes;
  };

  using Roots = std::array<Hash, nb_trees>;

  struct Proof {
    size_t tree_index;
    MerkleTree::Proof tree_proof;
  };

  MerkleForest() = default;  // Uninitialized tree.

  // We implement the = operator to spare the temporary...
  MerkleForest& operator=(std::array<Hash, t> const& hashes) {
    for (size_t i = 0, offset = 0; i < trees.size();
         i++, offset += MerkleTree::size) {
      trees[i] = *reinterpret_cast<std::array<Hash, MerkleTree::size> const*>(
          &hashes[offset]);
    }
    return *this;
  }
  // ... and make the constructor follow the same logic.
  MerkleForest(std::array<Hash, t> const& hashes) { *this = hashes; }

  Roots getRoots() const {
    Roots roots;
    for (size_t i = 0; i < trees.size(); i++) {
      roots[i] = trees[i].nodes[0];
    }
    return roots;
  }

  Proof prove(size_t leaf_index) const {
    if (leaf_index >= t) {
      throw std::runtime_error(
          fmt::format("Leaf index ({}) >= t ({}).", leaf_index, t));
    }
    auto const tree_index = leaf_index / MerkleTree::size;
    auto const tree_leaf_index = leaf_index % MerkleTree::size;
    return {tree_index, trees[tree_index].prove(tree_leaf_index)};
  }

  /**
   * @brief Check if a proof comes from this merkle tree.
   *
   */
  bool verify(Proof const& proof) const {
    if (proof.tree_index >= trees.size()) {
      return false;
    }
    if (!trees[proof.tree_index].verify(proof.tree_proof)) {
      return false;
    }
    return true;
  }

  bool verify(Roots const& roots) const {
    for (size_t i = 0; i < trees.size(); i++) {
      if (trees[i].nodes[0] != roots[i]) {
        return false;
      }
    }
    return true;
  }

  std::array<MerkleTree, secrets_per_signature> trees;
};

// template <size_t MessageSize>
// struct SignedMessage {
//   // size_t seq;
//   std::array<uint8_t, MessageSize> message;
//   Signature signature;
// };
// static_assert(offsetof(SignedMessage<128>, message) == sizeof(size_t));

uint64_t fast_hash(EdDsaCrypto::Signature const&);
uint64_t fast_hash(EdDsaCrypto::Signature const& signature) {
  return XXH64(&signature[0], sizeof(EdDsaCrypto::Signature), 0);
}

class PrivateKey {
 public:
  PrivateKey(AesPrng& prng) { prng.generate(&secrets[0][0], sizeof(secrets)); }

  Secret const& getSecret(size_t const index) const { return secrets[index]; }

 private:
  std::array<Secret, t> secrets;
  static_assert(sizeof(secrets) == sizeof(Secret) * t);
};

class PublicKey {
 public:
  struct Serialized {
    Serialized() = default;

    EdDsaCrypto::Signature roots_signature;
    std::array<Hash, t> expected_hashes;
  };

  PublicKey(PrivateKey const& private_key, EdDsaCrypto& eddsa_crypto) {
    for (size_t i = 0; i < t; i++) {
      expected_hashes[i] = crypto::hash::blake3(private_key.getSecret(i));
    }
    merkle_forest = expected_hashes;
    roots = merkle_forest.getRoots();
    roots_signature =
        eddsa_crypto.sign(reinterpret_cast<uint8_t*>(&roots), sizeof(roots));
  }

  PublicKey(Serialized const& serialized_pk)
      : expected_hashes{serialized_pk.expected_hashes},
        merkle_forest{expected_hashes},
        roots{merkle_forest.getRoots()},
        roots_signature{serialized_pk.roots_signature} {}

  void serialize(void* const dest) const {
    auto& serialized_dest = *reinterpret_cast<Serialized*>(dest);
    serialized_dest.roots_signature = roots_signature;
    serialized_dest.expected_hashes = expected_hashes;
  }

  /**
   * @brief Verify that the roots' signature matches.
   */
  bool verify(EdDsaCrypto& eddsa_crypto, ProcId const node_id) {
    return eddsa_crypto.verify(roots_signature,
                               reinterpret_cast<uint8_t*>(&roots),
                               sizeof(MerkleForest::Roots), node_id);
  }

  EdDsaCrypto::Signature const& getRootsSignature() const {
    return roots_signature;
  }

  MerkleForest const& getMerkleForest() const { return merkle_forest; }

 private:
  std::array<Hash, t> expected_hashes;
  MerkleForest merkle_forest;
  MerkleForest::Roots roots;
  EdDsaCrypto::Signature roots_signature;
};

struct Signature {
  EdDsaCrypto::Signature roots_signature;
  MerkleForest::Roots roots;
  std::array<std::pair<Secret, MerkleForest::Proof>, secrets_per_signature>
      secrets;

  /**
   * @brief Verify the Merkle component of a signature.
   *
   * Warning: This does NOT verify:
   *  - The Merkle proofs.
   *  - The HORS signature.
   */
  bool verifyRootsSignature(EdDsaCrypto& eddsa_crypto, ProcId node_id) const {
    return eddsa_crypto.verify(roots_signature,
                               reinterpret_cast<uint8_t const*>(&roots),
                               sizeof(roots), node_id);
  }

  /**
   * @brief Verify the Merkle component of a signature.
   *
   * Warning: This does NOT verify:
   *  - The roots' signature.
   *  - The HORS signature.
   */
  bool verifyMerkle() const {
    for (auto const& [_, proof] : secrets) {
      if (proof.tree_index >= MerkleForest::nb_trees) {
        return false;
      }
      if (!proof.tree_proof.verify(roots[proof.tree_index])) {
        return false;
      }
    }
    return true;
  }

  /**
   * @brief Verify the Merkle component of a signature faster with a public key.
   *
   * Warning: This does NOT verify:
   *  - The roots' signature.
   *  - The HORS signature.
   */
  bool verifyMerkle(MerkleForest const& merkle_forest) const {
    if (!merkle_forest.verify(roots)) {
      return false;
    }
    for (auto const& [_, proof] : secrets) {
      if (!merkle_forest.verify(proof)) {
        return false;
      }
    }
    return true;
  }

  /**
   * @brief Verify the HORS component of a signature.
   *
   * Warning: This does NOT verify:
   *  - The roots' signature.
   *  - The Merkle proofs.
   */
  bool verifyHors(uint8_t const* const begin, uint8_t const* const end) const {
    // 1. Check that the hashes' indices match the hash of the message.
    ExtendedHash h(begin, end);
    for (size_t hash_offset = 0, secret = 0; secret < secrets_per_signature;
         secret++, hash_offset += bits_per_secret) {
      auto const secret_index = h.getSecretIndex(hash_offset);
      auto const& proof = secrets[secret].second;
      if (secret_index != proof.tree_index * MerkleForest::MerkleTree::size +
                              proof.tree_proof.leaf_index) {
        fmt::print("The secret index didn't match the expected one.\n");
        return false;
      }
    }
    // 2. Check that the revealed secrets match the hashes.
    for (auto& secret : secrets) {
      if (crypto::hash::blake3(secret.first) != secret.second.tree_proof.leaf) {
        fmt::print("The secret's hash didn't match the expected one.\n");
        return false;
      }
    }
    return true;
  }
};

class Crypto {
 public:
  using Signature = pony::Signature;

  Crypto(EdDsaCrypto& eddsa_crypto)
      : eddsa_crypto{eddsa_crypto},
        private_key{std::make_unique<PrivateKey>(prng)},
        public_key{std::make_unique<PublicKey>(*private_key, eddsa_crypto)} {}

  // WARNING: THIS IS NOT THREAD SAFE
  void fetchPublicKey(ProcId const id) { eddsa_crypto.fetchPublicKey(id); }

  Signature sign(uint8_t const* msg,      // NOLINT
                 size_t const msg_len) {  // NOLINT
    // 1. Check if the SK is not exhausted: TODO
    // 2. Wait till a new SK is installed: TODO
    // 3. Sign with the SK.
    Signature signature;
    signature.roots = public_key->getMerkleForest().getRoots();
    signature.roots_signature = public_key->getRootsSignature();

    ExtendedHash h(msg, msg + msg_len);
    for (size_t hash_offset = 0, secret = 0; secret < secrets_per_signature;
         secret++, hash_offset += bits_per_secret) {
      auto const secret_index = h.getSecretIndex(hash_offset);
      signature.secrets[secret].first = private_key->getSecret(secret_index);
      signature.secrets[secret].second =
          public_key->getMerkleForest().prove(secret_index);
    }

    return signature;
  }

  /**
   * @brief Verify if a signature is valid.
   *
   * There are two paths for signature verification.
   *
   * 1) The EdDSA signature is checked (and cached).
   * 2) The Merkle proofs for expected hashes are checked.
   *   A) The hashes are compared if a full HORS-PK was received before.
   *   B) The hashes are computed if no HORS-PK was received.
   * 3) The HORS proof is checked.
   */
  bool verify(Signature const& sig, uint8_t const* msg, size_t const msg_len,
              ProcId const node_id) {
    // WARNING: not thread safe for now!!!
    // 1.
    auto const sig_hash = fast_hash(sig.roots_signature);
    auto vr_it = verified_roots.find(sig_hash);
    if (vr_it == verified_roots.end()) {
      // fmt::print("Never heard of this signature...\n");
      if (!sig.verifyRootsSignature(eddsa_crypto, node_id)) {
        fmt::print("Invalid root signature!\n");
        return false;
      }
      vr_it = verified_roots.try_emplace(sig_hash).first;
    }
    // 2.
    if (vr_it->second) {
      if (!sig.verifyMerkle(vr_it->second->getMerkleForest())) {
        fmt::print("Merkle proofs didn't match.\n");
        return false;
      }
    } else {
      if (!sig.verifyMerkle()) {
        fmt::print("Merkle proofs didn't pass.\n");
        return false;
      }
    }
    // DEBUG, let's uncache the key: verified_roots.erase(sig_hash);
    // 3.
    return sig.verifyHors(msg, msg + msg_len);
  }

  //// DEBUG ////
  PublicKey const& getPublicKey() { return *public_key; }
  void renewKeys() {
    using Clock = std::chrono::steady_clock;

    auto sk_gen_start = Clock::now();
    private_key = std::make_unique<PrivateKey>(prng);
    fmt::print("SK generated in {}\n", Clock::now() - sk_gen_start);
    auto pk_gen_start = Clock::now();
    public_key = std::make_unique<PublicKey>(*private_key, eddsa_crypto);
    fmt::print("PK generated in {}\n", Clock::now() - pk_gen_start);
  }
  void checkPublicKey(PublicKey::Serialized const& spk, ProcId const node_id) {
    auto pk = std::make_unique<PublicKey>(spk);
    if (!pk->verify(eddsa_crypto, node_id)) {
      fmt::print("Invalid serialize pk received\n");
    }
    verified_roots.emplace(fast_hash(pk->getRootsSignature()), std::move(pk));
  }

  inline ProcId myId() const { return eddsa_crypto.myId(); }

 private:
  EdDsaCrypto& eddsa_crypto;
  AesPrng prng;

  std::unique_ptr<PrivateKey> private_key;
  std::unique_ptr<PublicKey> public_key;
  size_t private_key_uses = 0;

  // Map: xxhash3(EdDSA Signature) -> Option<PublicKey>
  std::unordered_map<uint64_t, std::unique_ptr<PublicKey>> verified_roots;
};

}  // namespace dory::ubft::pony

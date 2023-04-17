#pragma once

#include <array>
#include <utility>
#include <variant>

#include <dory/crypto/asymmetric/dalek.hpp>
#include <dory/crypto/asymmetric/sodium.hpp>

namespace dory::crypto::asymmetric {

class AsymmetricCrypto {
 public:
  // The `PublicKey` is a variant (intead of a union) since it is safer, it
  // holds a pointer and it is not sent over the network
  using PublicKey = std::variant<dalek::pub_key, sodium::pub_key>;

  // The `PublicKeyView` returns the underlying raw public key data
  using PublicKeyView = std::pair<uint8_t const *, size_t>;

  static_assert(sizeof(dalek::signature) ==
                    sizeof(std::array<unsigned char, sodium::SignatureLength>),
                "The two implementation must have signatures of the same size");

  union Signature {
    dalek::signature dalek_sig;
    std::array<unsigned char, sodium::SignatureLength> sodium_sig;
  };

  using SignatureView = std::pair<uint8_t const *, size_t>;

  virtual PublicKeyView publicKeyView(PublicKey const &pk) const = 0;

  virtual SignatureView signatureView(Signature const &sig) const = 0;
  virtual SignatureView signatureView(uint8_t const *start) const = 0;
  virtual Signature signatureFromView(SignatureView const &view) const = 0;

  virtual void publishPublicKey(std::string const &mem_key) = 0;
  virtual PublicKey getPublicKey(std::string const &mem_key) = 0;

  virtual void sign(SignatureView &sig_view, unsigned char const *msg,
                    uint64_t msg_len) const = 0;
  virtual Signature sign(unsigned char const *msg, uint64_t msg_len) const = 0;

  virtual bool verify(Signature const &sig, unsigned char const *msg,
                      uint64_t msg_len, PublicKey &pk) const = 0;

  virtual ~AsymmetricCrypto() {}
};

class DalekAsymmetricCrypto : public AsymmetricCrypto {
 public:
  DalekAsymmetricCrypto(bool use_store) : use_store{use_store} {
    dalek::init();
  }

  bool avx() { return dalek::avx(); }

  PublicKeyView publicKeyView(PublicKey const &pk) const override {
    return {reinterpret_cast<uint8_t const *>(std::get<0>(pk).get()),
            dalek::PublicKeyLength};
  }

  SignatureView signatureView(Signature const &sig) const override {
    return {reinterpret_cast<uint8_t const *>(sig.dalek_sig.s),
            dalek::PublicKeyLength};
  }

  SignatureView signatureView(uint8_t const *start) const override {
    return {start, dalek::PublicKeyLength};
  }

  Signature signatureFromView(SignatureView const &view) const override {
    Signature sig;
    std::memcpy(sig.dalek_sig.s, view.first, dalek::SignatureLength);
    return sig;
  }

  void publishPublicKey(std::string const &mem_key) override {
    if (use_store) {
      dalek::publish_pub_key(mem_key);
    } else {
      dalek::publish_pub_key_nostore(mem_key);
    }
  }

  PublicKey getPublicKey(std::string const &mem_key) override {
    dalek::pub_key pk;
    if (use_store) {
      pk = dalek::get_public_key(mem_key);
    } else {
      pk = dalek::get_public_key_nostore(mem_key);
    }

    return pk;
  }

  void sign(SignatureView &sig_view, unsigned char const *msg,
            uint64_t msg_len) const override {
    dalek::sign(const_cast<uint8_t *>(sig_view.first), msg, msg_len);
  }

  Signature sign(unsigned char const *msg, uint64_t msg_len) const override {
    Signature sig;
    dalek::sign(sig.dalek_sig.s, msg, msg_len);
    return sig;
  }

  bool verify(Signature const &sig, unsigned char const *msg, uint64_t msg_len,
              PublicKey &pk) const override {
    return dalek::verify(sig.dalek_sig, msg, msg_len, std::get<0>(pk));
  }

 private:
  bool use_store;
};

class SodiumAsymmetricCrypto : public AsymmetricCrypto {
 public:
  SodiumAsymmetricCrypto(bool use_store) : use_store{use_store} {
    sodium::init();
  }

  PublicKeyView publicKeyView(PublicKey const &pk) const override {
    return {reinterpret_cast<uint8_t const *>(std::get<1>(pk).get()),
            sodium::PublicKeyLength};
  }

  SignatureView signatureView(Signature const &sig) const override {
    return {reinterpret_cast<uint8_t const *>(sig.sodium_sig.data()),
            sodium::PublicKeyLength};
  }

  SignatureView signatureView(uint8_t const *start) const override {
    return {start, sodium::PublicKeyLength};
  }

  Signature signatureFromView(SignatureView const &view) const override {
    Signature sig;
    std::memcpy(sig.sodium_sig.data(), view.first, sodium::SignatureLength);
    return sig;
  }

  void publishPublicKey(std::string const &mem_key) override {
    if (use_store) {
      sodium::publish_pub_key(mem_key);
    } else {
      sodium::publish_pub_key_nostore(mem_key);
    }
  }

  PublicKey getPublicKey(std::string const &mem_key) override {
    sodium::pub_key pk;
    if (use_store) {
      pk = sodium::get_public_key(mem_key);
    } else {
      pk = sodium::get_public_key_nostore(mem_key);
    }

    return pk;
  }

  void sign(SignatureView &sig_view, unsigned char const *msg,
            uint64_t msg_len) const override {
    sodium::sign(const_cast<uint8_t *>(sig_view.first), msg, msg_len);
  }

  Signature sign(unsigned char const *msg, uint64_t msg_len) const override {
    Signature sig;
    sodium::sign(sig.sodium_sig.data(), msg, msg_len);
    return sig;
  }

  bool verify(Signature const &sig, unsigned char const *msg, uint64_t msg_len,
              PublicKey &pk) const override {
    return sodium::verify(sig.sodium_sig.data(), msg, msg_len, std::get<1>(pk));
  }

 private:
  bool use_store;
};

}  // namespace dory::crypto::asymmetric

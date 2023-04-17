#include <chrono>
#include <iostream>
#include <memory>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>
#include <dory/shared/logger.hpp>

auto logger = dory::std_out_logger("MAIN");

int main(int argc, char* argv[]) {
  if (argc < 2 ||
      (std::string(argv[1]) != "dalek" && std::string(argv[1]) != "sodium")) {
    logger->info("Please provide `dalek` or `sodium` as argument");
    return 1;
  }

  std::unique_ptr<dory::crypto::asymmetric::AsymmetricCrypto> crypto;

  if (std::string(argv[1]) == "dalek") {
    crypto = std::make_unique<dory::crypto::asymmetric::DalekAsymmetricCrypto>(
        false);
    bool avx = dynamic_cast<dory::crypto::asymmetric::DalekAsymmetricCrypto*>(
                   crypto.get())
                   ->avx();
    logger->info("Dalek {} AVX", avx ? "uses" : "does not use");
  } else {
    crypto = std::make_unique<dory::crypto::asymmetric::SodiumAsymmetricCrypto>(
        false);
  }

  int iterations = 100000;

  char msg[] = "HELLO WORLD";
  uint64_t msg_len = 12;

  long long sign_microseconds = 0;
  long long verify_microseconds = 0;

  crypto->publishPublicKey("p1-pk");
  auto pk = crypto->getPublicKey("p1-pk");

  auto sig = crypto->sign(reinterpret_cast<unsigned char*>(msg), msg_len);

  {
    int successes = 0;
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
      successes += crypto->verify(
          sig, reinterpret_cast<unsigned char const*>(msg), msg_len, pk);
    }

    if (successes != iterations) {
      logger->error("Error in verifying ({} vs {})", successes, iterations);
      return 1;
    }

    auto elapsed = std::chrono::high_resolution_clock::now() - start;

    verify_microseconds =
        std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
  }

  dory::crypto::asymmetric::AsymmetricCrypto::Signature ret_sig;
  auto sig_view = crypto->signatureView(ret_sig);

  {
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
      crypto->sign(sig_view, reinterpret_cast<unsigned char*>(msg), msg_len);
    }
    auto elapsed = std::chrono::high_resolution_clock::now() - start;

    sign_microseconds =
        std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
  }

  logger->info("Verification takes {} us", verify_microseconds / iterations);
  logger->info("Signing takes {} us", sign_microseconds / iterations);

  logger->info("Testing finished successfully!");

  return 0;
}

#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <thread>
#include <vector>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>
#include <dory/shared/logger.hpp>
#include <dory/shared/pinning.hpp>
#include <dory/shared/types.hpp>
#include <dory/shared/units.hpp>
#include <dory/shared/unused-suppressor.hpp>

#include "../pony.hpp"

#include "tail-p2p/receiver-builder.hpp"
#include "tail-p2p/receiver.hpp"
#include "tail-p2p/sender-builder.hpp"
#include "tail-p2p/sender.hpp"

#include "../latency.hpp"

using namespace dory;
using namespace pony;
using namespace crypto;

// Note: to call after instanciating Pony so that its threads don't inherit the
// sched affinity.
static void pin_main(int const core_id) {
  if (core_id >= 0) {
    fmt::print("Pinning main thread to core {}\n", core_id);
    dory::pin_main_to_core(core_id);
  } else {
    fmt::print("Main thread is not pinned to a specific core\n");
  }
}

using ProcId = int;
using Clock = std::chrono::steady_clock;

struct Measurements {
  Measurements()
      : local_aggregate_time_signing{0},
        local_aggregate_time_verifying{0},
        remote_aggregate_time_signing{0},
        remote_aggregate_time_verifying{0},
        local_sign_profiling{1024},
        local_verify_profiling{1024},
        remote_sign_profiling{1024},
        remote_verify_profiling{1024},
        full_rtt_profiling{1024},
        overall_profiling{1024} {}

  std::chrono::nanoseconds local_aggregate_time_signing;
  std::chrono::nanoseconds local_aggregate_time_verifying;
  std::chrono::nanoseconds remote_aggregate_time_signing;
  std::chrono::nanoseconds remote_aggregate_time_verifying;

  dory::pony::LatencyProfiler local_sign_profiling;
  dory::pony::LatencyProfiler local_verify_profiling;
  dory::pony::LatencyProfiler remote_sign_profiling;
  dory::pony::LatencyProfiler remote_verify_profiling;
  dory::pony::LatencyProfiler full_rtt_profiling;
  dory::pony::LatencyProfiler overall_profiling;
};

enum Path { Fast, Slow };
char const* to_string(Path);
char const* to_string(Path const path) {
  switch (path) {
    case Fast:
      return "FAST";
    case Slow:
      return "SLOW";
    default:
      return "UNKNOWN";
  }
}

using Validity = Signature::Validity;

struct SignedMessage {
  Signature sig;

  std::chrono::nanoseconds remote_sign;
  std::chrono::nanoseconds remote_verify;

  uint8_t msg;

  std::chrono::nanoseconds fill(size_t const p, size_t const msg_size,
                                Pony& pony, Validity const validity) {
    std::memset(&msg, 0, msg_size);
    *reinterpret_cast<size_t*>(&msg) = p;

    auto const start = std::chrono::steady_clock::now();
    pony.sign(sig, &msg, msg_size);
    auto const end = std::chrono::steady_clock::now();

    damage(sig, validity);

    return end - start;
  }

  bool verify(size_t const msg_size, Pony& pony, Path const path,
              Validity const validity, ProcId const remote_id) const {
    auto const valid = path == Fast
                           ? pony.verify(sig, &msg, msg_size, remote_id)
                           : pony.slow_verify(sig, &msg, msg_size, remote_id);
    return (validity == Signature::Valid) ^ !valid;
  }

  void print(size_t const msg_size) const {
    auto const& siga =
        *reinterpret_cast<std::array<uint8_t, sizeof(Signature)> const*>(&sig);
    auto const& msga = *reinterpret_cast<std::array<uint8_t, 8> const*>(&msg);
    if (msg_size < 8) {
      throw std::runtime_error("msg size should be >= 8");
    }
    fmt::print("<Sig: {}, Msg: {}...>\n", siga, msga);
  }

  size_t static constexpr size(size_t const msg_size) {
    return offsetof(SignedMessage, msg) + msg_size;
  }

 private:
  void damage(HorsMerkleSignature& sig,
              HorsMerkleSignature::Validity const validity) {
    switch (validity) {
      case HorsMerkleSignature::Validity::Valid:
        break;
      case HorsMerkleSignature::Validity::InvalidPkHash:
        sig.pk_hash.back() ^= 1;
        break;
      case HorsMerkleSignature::Validity::InvalidPkSig:
        sig.pk_sig.sig.back() ^= 1;
        break;
      case HorsMerkleSignature::Validity::InvalidNonce:
        sig.nonce.back() ^= 1;
        break;
      case HorsMerkleSignature::Validity::InvalidRoots:
        sig.roots.back().back() ^= 1;
        break;
      case HorsMerkleSignature::Validity::InvalidSecret:
        sig.secrets.back().secret.back() ^= 1;
        break;
      case HorsMerkleSignature::Validity::InvalidMerkleProof:
        sig.secrets.back().proof.path.back().back() ^= 1;
        break;
      default:
        throw std::runtime_error("Unknown");
    }
  }

  void damage(HorsFullSignature& sig,
              HorsFullSignature::Validity const validity) {
    switch (validity) {
      case HorsFullSignature::Validity::Valid:
        break;
      case HorsFullSignature::Validity::InvalidPkHash:
        sig.pk_hash.back() ^= 1;
        break;
      case HorsFullSignature::Validity::InvalidPkSig:
        sig.pk_sig.sig.back() ^= 1;
        break;
      case HorsMerkleSignature::Validity::InvalidNonce:
        sig.nonce.back() ^= 1;
        break;
      case HorsFullSignature::Validity::InvalidSecret:
        sig.secrets_and_hashes.back().back() ^= 1;
        break;
      default:
        throw std::runtime_error("Unknown");
    }
  }

  void damage(HorsSyncSignature& sig,
              HorsSyncSignature::Validity const validity) {
    switch (validity) {
      case HorsSyncSignature::Validity::Valid:
        break;
      case HorsMerkleSignature::Validity::InvalidNonce:
        sig.nonce.back() ^= 1;
        break;
      case HorsSyncSignature::Validity::InvalidSecret:
        sig.secrets.back().back() ^= 1;
        break;
      default:
        throw std::runtime_error("Unknown");
    }
  }

  void damage(WotsSignature& sig, WotsSignature::Validity const validity) {
    switch (validity) {
      case WotsSignature::Validity::Valid:
        break;
      case WotsSignature::Validity::InvalidPkHash:
        sig.pk_hash.back() ^= 1;
        break;
      case WotsSignature::Validity::InvalidPkSig:
        sig.pk_sig.sig.back() ^= 1;
        break;
      case WotsSignature::Validity::InvalidNonce:
        sig.nonce.back() ^= 1;
        break;
      case WotsSignature::Validity::InvalidSecret:
        sig.secrets.back().back() ^= 1;
        break;
      default:
        throw std::runtime_error("Unknown");
    }
  }
};

/**
 * @brief A struct that encapsulates RDMA initialization.
 *
 */
struct P2p {
  P2p(ProcId const local_id, size_t const msg_size, size_t const slots = 1)
      : local_id{local_id}, remote_id{3 - local_id} {
    //// Setup RDMA ////
    LOGGER_INFO(logger, "Opening last RDMA device");
    open_device.emplace(std::move(ctrl::Devices().list().back()));
    LOGGER_INFO(logger, "Device: {} / {}, {}, {}", open_device->name(),
                open_device->devName(),
                ctrl::OpenDevice::typeStr(open_device->nodeType()),
                ctrl::OpenDevice::typeStr(open_device->transportType()));

    size_t binding_port = 0;
    LOGGER_INFO(logger, "Binding to port {} of opened device {}", binding_port,
                open_device->name());
    resolved_port.emplace(*open_device);
    if (!resolved_port->bindTo(binding_port)) {
      throw std::runtime_error("Couldn't bind the device.");
    }
    LOGGER_INFO(logger, "Binded successfully (port_id, port_lid) = ({}, {})",
                +resolved_port->portId(), +resolved_port->portLid());

    LOGGER_INFO(logger, "Configuring the control block");
    cb.emplace(*resolved_port);

    // //// Create Memory Regions and QPs ////
    cb->registerPd("standard");
    cb->registerCq("unused");

    auto& store = memstore::MemoryStore::getInstance();

    tail_p2p::SenderBuilder sender_builder(*cb, local_id, remote_id, "main", 32,
                                           msg_size);
    tail_p2p::ReceiverBuilder receiver_builder(*cb, local_id, remote_id, "main",
                                               32, msg_size);
    sender_builder.announceQps();
    receiver_builder.announceQps();

    store.barrier("qp_announced", 2);

    sender_builder.connectQps();
    receiver_builder.connectQps();

    store.barrier("qp_connected", 2);

    sender.emplace(sender_builder.build());
    receiver.emplace(receiver_builder.build());

    store.barrier("abstractions_initialized", 2);
  }

  ProcId local_id;
  ProcId remote_id;

 private:
  Delayed<ctrl::OpenDevice> open_device;
  Delayed<ctrl::ResolvedPort> resolved_port;
  Delayed<ctrl::ControlBlock> cb;

 public:  // Order matters for destruction
  Delayed<tail_p2p::Sender> sender;
  Delayed<tail_p2p::Receiver> receiver;

  LOGGER_DECL_INIT(logger, "P2p");
};

static void ping_test(size_t& dummy_msg, size_t const pings,
                      size_t const msg_size, P2p& p2p, Pony& pony,
                      Measurements& msr, Path const path,
                      Validity const validity, bool const check = false) {
  auto& sender = *p2p.sender;
  auto& receiver = *p2p.receiver;

  for (size_t p = 0; p < pings; p++) {
    Clock::time_point left_sender;
    Clock::time_point arrived_sender;

    std::chrono::nanoseconds aggregate{0};

    // Sign + Send for measurer
    if (p2p.local_id == 1) {
      auto& sm = *reinterpret_cast<SignedMessage*>(sender.getSlot(
          static_cast<tail_p2p::Size>(SignedMessage::size(msg_size))));
      auto time_to_sign = sm.fill(dummy_msg++, msg_size, pony, validity);
      msr.local_aggregate_time_signing += time_to_sign;
      msr.local_sign_profiling.addMeasurement(time_to_sign);

      if (check && !sm.verify(msg_size, pony, path, validity, p2p.local_id)) {
        throw std::runtime_error(fmt::format(
            "[Ping: {}/{}, Path: {}, Validity: {}] LOCAL VERIFICATION FAILED",
            p, pings, to_string(path), Signature::to_string(validity)));
      }

      left_sender = Clock::now();
      sender.send();

      aggregate += time_to_sign;
    }

    // Used by proc 1 and 2
    std::chrono::nanoseconds time_to_verify;

    // Recv + Verify
    {
      auto polled = receiver.poll();
      while (!polled) {
        sender.tickForCorrectness();
        polled = receiver.poll();
      }

      arrived_sender = Clock::now();

      auto& sm = *reinterpret_cast<SignedMessage const*>(polled->msg());
      auto const verify_start = std::chrono::steady_clock::now();
      if (!sm.verify(msg_size, pony, path, validity, p2p.remote_id)) {
        throw std::runtime_error(fmt::format(
            "[Ping: {}/{}, Path: {}, Validity: {}] TEST FAILED", p, pings,
            to_string(path), Signature::to_string(validity)));
      }
      time_to_verify = (std::chrono::steady_clock::now() - verify_start);
      msr.local_verify_profiling.addMeasurement(time_to_verify);
      msr.local_aggregate_time_verifying += time_to_verify;

      msr.remote_aggregate_time_signing += sm.remote_sign;
      msr.remote_aggregate_time_verifying += sm.remote_verify;
      msr.remote_sign_profiling.addMeasurement(sm.remote_sign);
      msr.remote_verify_profiling.addMeasurement(sm.remote_verify);

      auto full_rtt =
          arrived_sender - left_sender - sm.remote_sign - sm.remote_verify;
      msr.full_rtt_profiling.addMeasurement(full_rtt);

      aggregate += full_rtt / 2;
      aggregate += time_to_verify;

      msr.overall_profiling.addMeasurement(aggregate);
    }

    // Sign + Send for measurer
    if (p2p.local_id == 2) {
      auto& sm = *reinterpret_cast<SignedMessage*>(sender.getSlot(
          static_cast<tail_p2p::Size>(SignedMessage::size(msg_size))));
      auto time_to_sign = sm.fill(dummy_msg++, msg_size, pony, validity);

      if (check && !sm.verify(msg_size, pony, path, validity, p2p.local_id)) {
        throw std::runtime_error(fmt::format(
            "[Ping: {}/{}, Path: {}, Validity: {}] LOCAL VERIFICATION FAILED",
            p, pings, to_string(path), Signature::to_string(validity)));
      }

      // Proc 2 sends the that it spent to sign and verify to Proc 1
      sm.remote_sign = time_to_sign;
      sm.remote_verify = time_to_verify;

      sender.send();
    }
  }
}

struct EddsaMessage {
  asymmetric::AsymmetricCrypto::Signature sig;

  std::chrono::nanoseconds remote_sign;
  std::chrono::nanoseconds remote_verify;

  uint8_t msg;

  std::chrono::nanoseconds fill(size_t const p, size_t const msg_size,
                                asymmetric::AsymmetricCrypto& crypto,
                                const bool bypass) {
    auto sig_view = crypto.signatureView(sig);
    std::memset(&msg, 0, msg_size);
    *reinterpret_cast<size_t*>(&msg) = p;
    if (bypass) {
      return std::chrono::nanoseconds(0);
    }

    auto const start = std::chrono::steady_clock::now();
    crypto.sign(sig_view, &msg, msg_size);
    auto const end = std::chrono::steady_clock::now();

    return end - start;
  }

  bool verify(size_t const msg_size, asymmetric::AsymmetricCrypto& crypto,
              asymmetric::AsymmetricCrypto::PublicKey& pk,
              const bool bypass) const {
    if (bypass) {
      return true;
    }
    return crypto.verify(sig, &msg, msg_size, pk);
  }

  size_t static constexpr size(size_t const msg_size) {
    return offsetof(EddsaMessage, msg) + msg_size;
  }
};

static void ping_test_eddsa(size_t& dummy_msg, size_t const pings,
                            size_t const msg_size, P2p& p2p,
                            asymmetric::AsymmetricCrypto& crypto,
                            asymmetric::AsymmetricCrypto::PublicKey& local_pk,
                            asymmetric::AsymmetricCrypto::PublicKey& remote_pk,
                            bool const bypass = false) {
  auto& sender = *p2p.sender;
  auto& receiver = *p2p.receiver;
  Clock::time_point const start = Clock::now();

  std::chrono::nanoseconds local_aggregate_time_signing{0};
  std::chrono::nanoseconds local_aggregate_time_verifying{0};
  std::chrono::nanoseconds remote_aggregate_time_signing{0};
  std::chrono::nanoseconds remote_aggregate_time_verifying{0};

  dory::pony::LatencyProfiler local_sign_profiling;
  dory::pony::LatencyProfiler local_verify_profiling;
  dory::pony::LatencyProfiler remote_sign_profiling;
  dory::pony::LatencyProfiler remote_verify_profiling;
  dory::pony::LatencyProfiler full_rtt_profiling;

  for (size_t p = 0; p < pings; p++) {
    Clock::time_point left_sender;
    Clock::time_point arrived_sender;

    // Sign + Send for measurer
    if (p2p.local_id == 1) {
      auto* slot = sender.getSlot(
          static_cast<tail_p2p::Size>(EddsaMessage::size(msg_size)));
      auto& sm = *reinterpret_cast<EddsaMessage*>(slot);
      auto time_to_sign = sm.fill(dummy_msg++, msg_size, crypto, bypass);
      local_aggregate_time_signing += time_to_sign;
      local_sign_profiling.addMeasurement(time_to_sign);

      left_sender = Clock::now();
      sender.send();
    }

    // Used by proc 1 and 2
    std::chrono::nanoseconds time_to_verify;

    // Recv + Verify
    {
      auto polled = receiver.poll();
      while (!polled) {
        sender.tickForCorrectness();
        polled = receiver.poll();
      }

      arrived_sender = Clock::now();

      auto& sm = *reinterpret_cast<EddsaMessage const*>(polled->msg());
      auto const verify_start = std::chrono::steady_clock::now();
      if (!sm.verify(msg_size, crypto, remote_pk, bypass)) {
        throw std::runtime_error(
            fmt::format("[Ping: {}/{}] TEST FAILED", p, pings));
      }
      time_to_verify = (std::chrono::steady_clock::now() - verify_start);
      local_verify_profiling.addMeasurement(time_to_verify);
      local_aggregate_time_verifying += time_to_verify;

      remote_aggregate_time_signing += sm.remote_sign;
      remote_aggregate_time_verifying += sm.remote_verify;
      remote_sign_profiling.addMeasurement(sm.remote_sign);
      remote_verify_profiling.addMeasurement(sm.remote_verify);

      auto full_rtt =
          arrived_sender - left_sender - sm.remote_sign - sm.remote_verify;
      full_rtt_profiling.addMeasurement(full_rtt);
    }

    // Sign + Send for measurer
    if (p2p.local_id == 2) {
      auto* slot = sender.getSlot(
          static_cast<tail_p2p::Size>(EddsaMessage::size(msg_size)));
      auto& sm = *reinterpret_cast<EddsaMessage*>(slot);
      auto time_to_sign = sm.fill(dummy_msg++, msg_size, crypto, bypass);

      // Proc 2 sends the that it spent to sign and verify to Proc 1
      sm.remote_sign = time_to_sign;
      sm.remote_verify = time_to_verify;

      sender.send();
    }
  }

  if (p2p.local_id == 1) {
    std::chrono::nanoseconds const duration(Clock::now() - start);
    auto const ping_sign = local_aggregate_time_signing / pings;
    auto const ping_verify = local_aggregate_time_verifying / pings;
    auto const remote_sign = remote_aggregate_time_signing / pings;
    auto const remote_verify = remote_aggregate_time_verifying / pings;
    auto const ping_network = (duration / pings - ping_sign - ping_verify -
                               remote_sign - remote_verify) /
                              2;

    fmt::print(
        "[Size={}, Pings={}] "
        "latency: {} (signing: {}, verifying: {}, half-network-rtt: {})\n",
        msg_size, pings, duration / pings / 2, ping_sign, ping_verify,
        ping_network);

    fmt::print("\nSign\n");
    local_sign_profiling.report();

    fmt::print("\nVerify\n");
    local_verify_profiling.report();

    fmt::print("\nRemote Sign\n");
    remote_sign_profiling.report();

    fmt::print("\nRemote Verify\n");
    remote_verify_profiling.report();

    fmt::print("\nRTT\n");
    full_rtt_profiling.report();
  }
}

int main(int argc, char* argv[]) {
  fmt::print("Build Time: {}\n", BINARY_BUILD_TIME);

  lyra::cli cli;
  bool get_help = false;
  int local_id;
  size_t pings = pony::SkCtxs * pony::SignaturesPerSecretKey;
  size_t runs = 8;
  tail_p2p::Size msg_size = units::bytes(8);
  bool test_invalid = false;
  bool test_slow_path = false;
  int core_id = -1;
  std::string scheme;
  std::optional<size_t> burst;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(scheme, "pony,sodium,dalek")
                        .required()
                        .choices("pony", "sodium", "dalek", "none")
                        .name("--scheme")
                        .help("Which crypto scheme to use"))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("-l")
                        .name("--local-id")
                        .help("ID of the present process"))
      .add_argument(
          lyra::opt(pings, "pings").name("-p").name("--pings").help("Pings"))
      .add_argument(
          lyra::opt(runs, "runs").name("-r").name("--runs").help("Runs"))
      .add_argument(lyra::opt(msg_size, "msg_size")
                        .name("-s")
                        .name("--msg_size")
                        .help("Size of messages"))
      .add_argument(lyra::opt(test_invalid)
                        .name("-i")
                        .name("--test-invalid")
                        .help("Benchmark invalid signatures"))
      .add_argument(lyra::opt(test_slow_path)
                        .name("-S")
                        .name("--test-slow-path")
                        .help("Benchmark the slow path"))
      .add_argument(lyra::opt(core_id, "core_id")
                        .name("--core-pinning")
                        .help("Pin main thread to a particular core"))
      .add_argument(lyra::opt(burst, "burst")
                        .name("-b")
                        .name("--burst")
                        .help("Number of runs between each sleep"));

  // Parse the program arguments.
  auto result = cli.parse({argc, argv});

  if (get_help) {
    std::cout << cli;
    return 0;
  }

  if (!result) {
    std::cerr << "Error in command line: " << result.errorMessage()
              << std::endl;
    return 1;
  }

  auto& store = dory::memstore::MemoryStore::getInstance();
  ProcId const remote_id = local_id == 1 ? 2 : 1;

  fmt::print("Used crypto scheme: {}\n", scheme);

  if (scheme == "sodium" || scheme == "dalek" || scheme == "none") {
    pin_main(core_id);
    std::unique_ptr<asymmetric::AsymmetricCrypto> crypto;

    if (scheme == "dalek") {
      crypto = std::make_unique<asymmetric::DalekAsymmetricCrypto>(true);
      bool avx =
          dynamic_cast<asymmetric::DalekAsymmetricCrypto*>(crypto.get())->avx();
      fmt::print("Dalek {} AVX\n", avx ? "uses" : "does not use");
    } else {
      crypto = std::make_unique<asymmetric::SodiumAsymmetricCrypto>(true);
    }

    crypto->publishPublicKey(fmt::format("p{}-pk", local_id));

    store.barrier("public_keys_announced", 2);

    auto local_pk = crypto->getPublicKey(fmt::format("p{}-pk", local_id));
    auto remote_pk = crypto->getPublicKey(fmt::format("p{}-pk", remote_id));

    P2p p2p(local_id, EddsaMessage::size(msg_size));

    size_t dummy_msg = 0;
    for (size_t run = 0; run < runs; run++) {
      ping_test_eddsa(dummy_msg, pings, msg_size, p2p, *crypto, local_pk,
                      remote_pk, scheme == "none");
    }
  } else if (scheme == "pony") {
    Pony pony(local_id, false);
    pin_main(core_id);
    P2p p2p(local_id, SignedMessage::size(msg_size));

    std::vector<Path> paths = {Fast};
    if (test_slow_path) {
      paths.insert(paths.end(), {Slow});
    }

    size_t dummy_msg = 0;
    for (auto const path : paths) {
      // Setting the tests depending on the path.
      std::vector<Validity> tests = {Validity::Valid};
      if (test_invalid) {
        for (auto const invalid : Signature::InvalidFast) {
          tests.push_back(invalid);
        }
        if (path == Slow) {
          for (auto const invalid : Signature::InvalidSlow) {
            tests.push_back(invalid);
          }
        }
      }

      for (auto const validity : tests) {
        Measurements msr;
        std::chrono::nanoseconds duration;

        for (size_t run = 0; run < runs; run++) {
          if (run == 0 || (burst && (run % *burst) == 0)) {
            std::string run_barrier{""};
            while (!pony.replenished_sks() || !pony.replenished_pks(remote_id))
              ;
            auto const b1 = fmt::format("br-1-{}-{}-{}", run, validity, path);
            auto const b2 = fmt::format("br-2-{}-{}-{}", run, validity, path);
            if (local_id == 1) {
              // Master
              store.set(b1, "1");
              while (!store.get(b2, run_barrier)) {
                run_barrier.resize(0);
              }
            } else {
              // Slave
              while (!store.get(b1, run_barrier)) {
                run_barrier.resize(0);
              }
              store.set(b2, "1");
            }
          }
          auto start = Clock::now();
          ping_test(dummy_msg, pings, msg_size, p2p, pony, msr, path, validity);
          auto stop = Clock::now();

          duration += stop - start;
        }

        // Print the measurements
        if (local_id == 1) {
          auto iterations = pings * runs;
          auto const ping_sign = msr.local_aggregate_time_signing / iterations;
          auto const ping_verify =
              msr.local_aggregate_time_verifying / iterations;
          auto const remote_sign =
              msr.remote_aggregate_time_signing / iterations;
          auto const remote_verify =
              msr.remote_aggregate_time_verifying / iterations;
          auto const ping_network =
              (duration / iterations - ping_sign - ping_verify - remote_sign -
               remote_verify) /
              2;

          fmt::print(
              "[Size={}/Path={}/Validity={}, Pings={}] "
              "latency: {} (signing: {}, verifying: {}, half-network-rtt: "
              "{})\n",
              msg_size, to_string(path), Signature::to_string(validity),
              iterations, duration / iterations / 2, ping_sign, ping_verify,
              ping_network);

          fmt::print("\nOne-way\n");
          msr.overall_profiling.report();

          fmt::print("\nSign\n");
          msr.local_sign_profiling.report();

          fmt::print("\nVerify\n");
          msr.local_verify_profiling.report();

          fmt::print("\nRemote Sign\n");
          msr.remote_sign_profiling.report();

          fmt::print("\nRemote Verify\n");
          msr.remote_verify_profiling.report();

          fmt::print("\nRTT\n");
          msr.full_rtt_profiling.report();
        }
      }
    }

    // if (local_id == 1) {
    //   pony.report_latencies();
    // }
  }

  fmt::print("###DONE###\n");

  return 0;
}

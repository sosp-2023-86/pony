#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <thread>
#include <vector>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include <dory/pony/pony.hpp>
#include <dory/shared/logger.hpp>
#include <dory/shared/types.hpp>
#include <dory/shared/units.hpp>
#include <dory/shared/unused-suppressor.hpp>

#include "tail-p2p/receiver-builder.hpp"
#include "tail-p2p/receiver.hpp"
#include "tail-p2p/sender-builder.hpp"
#include "tail-p2p/sender.hpp"

using namespace dory;
using namespace pony_apps;

using ProcId = int;
using Clock = std::chrono::steady_clock;

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

enum Validity {
  Valid,
  NoSignature,
  InvalidRoots,
  InvalidRootsSig,
  InvalidSecret,
  InvalidMerkleProof
};

static char const* to_string(Validity const validity) {
  switch (validity) {
    case Valid:
      return "VALID";
    case NoSignature:
      return "NO_SIGNATURE";
    case InvalidRoots:
      return "INVALID_ROOTS";
    case InvalidRootsSig:
      return "INVALID_ROOTS_SIG";
    case InvalidSecret:
      return "INVALID_SECRET";
    case InvalidMerkleProof:
      return "INVALID_MERKLE_PROOF";
    default:
      return "UNKNOWN";
  }
}

struct SignedMessage {
  pony::Signature sig;
  uint8_t msg;

  std::chrono::nanoseconds fill(size_t const p, size_t const msg_size,
                                pony::Pony& pony, Validity const validity) {
    std::memset(&msg, 0, msg_size);
    *reinterpret_cast<size_t*>(&msg) = p;
    if (validity == NoSignature) {
      return std::chrono::nanoseconds(0);
    }

    auto const start = std::chrono::steady_clock::now();
    pony.sign(sig, &msg, msg_size);
    auto const end = std::chrono::steady_clock::now();

    switch (validity) {
      case Valid:
        break;
      case InvalidRoots:
        sig.roots.back().back() ^= 1;
        break;
      case InvalidRootsSig:
        sig.roots_sig.sig.back() ^= 1;
        break;
      case InvalidSecret:
        sig.secrets.back().secret.back() ^= 1;
        break;
      case InvalidMerkleProof:
        sig.secrets.back().proof.path.back().back() ^= 1;
        break;
      default:
        throw std::runtime_error("Unknown");
    }

    return end - start;
  }

  bool verify(size_t const msg_size, pony::Pony& pony, Path const path,
              Validity const validity, ProcId const remote_id) const {
    if (validity == NoSignature) {
      return true;
    }
    auto const valid = path == Fast
                           ? pony.verify(sig, &msg, msg_size, remote_id)
                           : pony.slow_verify(sig, &msg, msg_size, remote_id);
    return (validity == Valid) ^ !valid;
  }

  void print(size_t const msg_size) const {
    auto const& siga =
        *reinterpret_cast<std::array<uint8_t, sizeof(pony::Signature)> const*>(
            &sig);
    auto const& msga = *reinterpret_cast<std::array<uint8_t, 8> const*>(&msg);
    if (msg_size != 8) {
      throw std::runtime_error("msg size should be 8");
    }
    fmt::print("<Sig: {}, Msg: {}>\n", siga, msga);
  }

  size_t static constexpr size(size_t const msg_size) {
    return offsetof(SignedMessage, msg) + msg_size;
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
    size_t const device_idx = 0;
    LOGGER_INFO(logger, "Opening RDMA device {}", device_idx);
    open_device.emplace(std::move(ctrl::Devices().list()[device_idx]));
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

    tail_p2p::SenderBuilder sender_builder(*cb, local_id, remote_id, "main", 1,
                                           msg_size);
    tail_p2p::ReceiverBuilder receiver_builder(*cb, local_id, remote_id, "main",
                                               1, msg_size);
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

static void ping_test(size_t const pings, size_t const msg_size, P2p& p2p,
                      pony::Pony& pony, Path const path,
                      Validity const validity,
                      std::vector<uint8_t>& receive_buffer,
                      bool const check = false) {
  auto& sender = *p2p.sender;
  auto& receiver = *p2p.receiver;
  Clock::time_point const start = Clock::now();
  std::chrono::nanoseconds time_signing{0};
  std::chrono::nanoseconds time_verifying{0};
  for (size_t p = 0; p < pings; p++) {
    // Sign + Send for measurer
    if (p2p.local_id == 1) {
      auto& sm = *reinterpret_cast<SignedMessage*>(sender.getSlot(
          static_cast<tail_p2p::Size>(SignedMessage::size(msg_size))));
      time_signing += sm.fill(p, msg_size, pony, validity);
      if (check && !sm.verify(msg_size, pony, path, validity, p2p.local_id)) {
        throw std::runtime_error(fmt::format(
            "[Ping: {}/{}, Path: {}, Validity: {}] LOCAL VERIFICATION FAILED",
            p, pings, to_string(path), to_string(validity)));
      }
      sender.send();
    }
    // Recv + Verify
    {
      while (!receiver.poll(receive_buffer.data())) {
        sender.tickForCorrectness();
      }
      auto& sm = *reinterpret_cast<SignedMessage const*>(receive_buffer.data());
      auto const verify_start = std::chrono::steady_clock::now();
      if (!sm.verify(msg_size, pony, path, validity, p2p.remote_id)) {
        throw std::runtime_error(
            fmt::format("[Ping: {}/{}, Path: {}, Validity: {}] TEST FAILED", p,
                        pings, to_string(path), to_string(validity)));
      }
      time_verifying += (std::chrono::steady_clock::now() - verify_start);
    }
    // Sign + Send for measurer
    if (p2p.local_id == 2) {
      auto& sm = *reinterpret_cast<SignedMessage*>(sender.getSlot(
          static_cast<tail_p2p::Size>(SignedMessage::size(msg_size))));
      sm.fill(p, msg_size, pony, validity);
      if (check && !sm.verify(msg_size, pony, path, validity, p2p.local_id)) {
        throw std::runtime_error(fmt::format(
            "[Ping: {}/{}, Path: {}, Validity: {}] LOCAL VERIFICATION FAILED",
            p, pings, to_string(path), to_string(validity)));
      }
      sender.send();
    }
  }
  if (p2p.local_id == 1) {
    std::chrono::nanoseconds const duration(Clock::now() - start);
    auto const ping_total = duration / pings / 2;
    auto const ping_sign = time_signing / pings;
    auto const ping_verify = time_verifying / pings;
    auto const ping_network = ping_total - ping_sign - ping_verify;
    fmt::print(
        "[Size={}/Path={}/Validity={}] {} pings in {}, measured one-way "
        "latency: {} (signing: {}, verifying: {}, ~network: {})\n",
        msg_size, to_string(path), to_string(validity), pings, duration,
        ping_total, ping_sign, ping_verify, ping_network);
  }
}

int main(int argc, char* argv[]) {
  fmt::print("Build Time: {}\n", BINARY_BUILD_TIME);

  lyra::cli cli;
  bool get_help = false;
  int local_id;
  size_t pings = 32;
  size_t runs = 8;
  tail_p2p::Size msg_size = units::bytes(8);
  bool test_invalid = false;
  bool test_slow_path = false;

  cli.add_argument(lyra::help(get_help))
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
                        .name("-p")
                        .name("--test-slow-path")
                        .help("Benchmark the slow path"));

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

  pony::Pony pony(local_id, false);
  std::this_thread::sleep_for(
      std::chrono::seconds(1));  // For PKs to be buffered.
  P2p p2p(local_id, SignedMessage::size(msg_size));
  std::vector<uint8_t> receive_buffer(SignedMessage::size(msg_size), 0);

  std::vector<Validity> tests = {Valid};
  if (test_invalid) {
    tests.insert(tests.end(), {NoSignature, InvalidRoots, InvalidRootsSig,
                               InvalidSecret, InvalidMerkleProof});
  }

  std::vector<Path> paths = {Fast};
  if (test_slow_path) {
    paths.insert(paths.end(), {Slow});
  }

  for (auto const path : paths) {
    for (auto const validity : tests) {
      for (size_t run = 0; run < runs; run++) {
        ping_test(pings, msg_size, p2p, pony, path, validity, receive_buffer);
      }
    }
  }

  return 0;
}

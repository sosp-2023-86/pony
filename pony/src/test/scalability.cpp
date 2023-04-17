#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <random>
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
        remote_aggregate_time_verifying{0},
        in_buffer_profiling{1024},
        local_sign_profiling{1024},
        remote_verify_profiling{1024},
        network_profiling{1024},
        overall_profiling{1024} {}

  std::chrono::nanoseconds local_aggregate_time_signing;
  std::chrono::nanoseconds remote_aggregate_time_verifying;

  dory::pony::LatencyProfiler in_buffer_profiling;
  dory::pony::LatencyProfiler local_sign_profiling;
  dory::pony::LatencyProfiler remote_verify_profiling;
  dory::pony::LatencyProfiler network_profiling;
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

struct SignedMessage {
  std::chrono::nanoseconds local_sign;
  std::chrono::nanoseconds remote_verify;

  Signature sig;
  uint8_t msg;

  std::chrono::nanoseconds fill(size_t const p, size_t const msg_size,
                                Pony& pony) {
    std::memset(&msg, 0, msg_size);
    *reinterpret_cast<size_t*>(&msg) = p;

    auto const start = std::chrono::steady_clock::now();
    pony.sign(sig, &msg, msg_size);
    auto const end = std::chrono::steady_clock::now();

    return end - start;
  }

  bool verify(size_t const msg_size, Pony& pony, Path const path,
              ProcId const remote_id) const {
    auto const valid = path == Fast
                           ? pony.verify(sig, &msg, msg_size, remote_id)
                           : pony.slow_verify(sig, &msg, msg_size, remote_id);
    return valid;
  }

  size_t static constexpr size(size_t const msg_size) {
    return offsetof(SignedMessage, msg) + msg_size;
  }

  size_t static constexpr pong_size() { return offsetof(SignedMessage, sig); }
};

/**
 * @brief A struct that encapsulates RDMA initialization.
 *
 */
struct P2p {
  P2p(ProcId const local_id, std::vector<ProcId> const& remote_ids,
      size_t const msg_size, size_t const slots)
      : local_id{local_id}, remote_ids{remote_ids} {
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

    std::vector<tail_p2p::AsyncSenderBuilder> sender_builders;
    std::vector<tail_p2p::ReceiverBuilder> receiver_builders;
    for (auto const& remote_id : remote_ids) {
      sender_builders.emplace_back(*cb, local_id, remote_id, "main", slots,
                                   msg_size);
      sender_builders.back().announceQps();
      receiver_builders.emplace_back(*cb, local_id, remote_id, "main", slots,
                                     msg_size);
      receiver_builders.back().announceQps();
    }

    store.barrier("qp_announced", remote_ids.size() + 1);

    for (auto& sender_builder : sender_builders) {
      sender_builder.connectQps();
    }
    for (auto& receiver_builder : receiver_builders) {
      receiver_builder.connectQps();
    }

    store.barrier("qp_connected", remote_ids.size() + 1);

    for (auto& sender_builder : sender_builders) {
      senders.emplace_back(sender_builder.build());
    }
    for (auto& receiver_builder : receiver_builders) {
      receivers.emplace_back(receiver_builder.build());
    }

    store.barrier("abstractions_initialized", remote_ids.size() + 1);
  }

  ProcId local_id;
  std::vector<ProcId> remote_ids;

 private:
  Delayed<ctrl::OpenDevice> open_device;
  Delayed<ctrl::ResolvedPort> resolved_port;
  Delayed<ctrl::ControlBlock> cb;

 public:  // Order matters for destruction
  std::vector<tail_p2p::Sender> senders;
  std::vector<tail_p2p::Receiver> receivers;

  LOGGER_DECL_INIT(logger, "P2p");
};

class Requests {
 public:
  Requests(Pony& pony, std::vector<ProcId> const& verifiers,
           size_t const max_outstanding)
      : pony{pony}, verifiers{verifiers}, max_outstanding{max_outstanding} {
    for (auto const& _ : verifiers) {
      outstanding.emplace_back();
      outstanding.back().resize(max_outstanding);
      outstanding.back().resize(0);
    }
  }

  virtual bool poll() = 0;

  struct Measure {
    std::chrono::nanoseconds local_sign;
    std::chrono::nanoseconds remote_verify;
  };
  void done(size_t const index, Measure const& msr) {
    static constexpr std::chrono::nanoseconds ack{1000};
    auto const ponged_at = std::chrono::steady_clock::now();
    auto const& completed = outstanding[index].front();
    auto const ping_pong = ponged_at - completed.received_at;
    auto const in_buffer = completed.polled_at - completed.received_at;
    // Warning: Includes the remote ingress buffer, and ack is HARDCODED.
    auto const network =
        ping_pong - in_buffer - msr.local_sign - msr.remote_verify - ack;
    auto const end_to_end = ping_pong - ack;

    msrs.local_aggregate_time_signing += msr.local_sign;
    msrs.remote_aggregate_time_verifying += msr.remote_verify;
    msrs.in_buffer_profiling.addMeasurement(in_buffer);
    msrs.local_sign_profiling.addMeasurement(msr.local_sign);
    msrs.remote_verify_profiling.addMeasurement(msr.remote_verify);
    msrs.network_profiling.addMeasurement(network);
    msrs.overall_profiling.addMeasurement(end_to_end);
    outstanding[index].pop_front();
  }

  struct Request {
    std::chrono::steady_clock::time_point received_at;
    std::chrono::steady_clock::time_point polled_at;
  };
  std::vector<std::deque<Request>> outstanding;

  Measurements msrs;
  static constexpr std::chrono::microseconds DropAfter =
      std::chrono::microseconds(200);

  Pony& pony;
  std::vector<ProcId> const verifiers;
  size_t const max_outstanding;
};

struct ConstantRequests : public Requests {
 public:
  ConstantRequests(Pony& pony, std::vector<ProcId> const& verifiers,
                   size_t const max_outstanding,
                   std::chrono::nanoseconds const distance)
      : Requests{pony, verifiers, max_outstanding}, distance{distance} {}

  bool poll() override {
    auto const any_full = [&]() {
      for (auto const& out : outstanding) {
        if (out.size() >= max_outstanding) {
          return true;
        }
      }
      return false;
    }();
    if (any_full) {
      while (!pony.replenished_sks()) {
      }
      return false;
    }
    auto const now = std::chrono::steady_clock::now();
    if (last_received && now - *last_received < distance) {
      return false;
    }
    auto const received =
        (last_received && now - (*last_received + distance) < DropAfter)
            ? *last_received + distance
            : now;
    for (auto& out : outstanding) {
      out.emplace_back(Request{received, now});
    }
    last_received = received;
    return true;
  }

  std::chrono::nanoseconds const distance;
  std::optional<std::chrono::steady_clock::time_point> last_received;
  std::optional<std::chrono::steady_clock::time_point> to_poll;
};

enum Role { Signer, Verifier };

static bool run_test(Role const role, size_t& dummy_msg, size_t const pings,
                     size_t const msg_size, P2p& p2p, Pony& pony,
                     Requests& reqs, Path const path,
                     std::chrono::seconds const timeout) {
  auto& senders = p2p.senders;
  auto& receivers = p2p.receivers;
  size_t done = 0;
  std::vector<uint8_t> msg_buffer;
  msg_buffer.resize(SignedMessage::size(msg_size));
  auto& sm = *reinterpret_cast<SignedMessage*>(msg_buffer.data());

  auto const remotes = p2p.receivers.size();
  auto const start = std::chrono::steady_clock::now();

  if (role == Signer) {
    // Master: signer + measurer
    while (done < pings * remotes) {
      if (reqs.poll()) {
        // fmt::print("Should send a sig!\n");
        sm.local_sign = sm.fill(dummy_msg++, msg_size, pony);
        for (auto& sender : senders) {
          auto* const slot =
              sender.getSlot(static_cast<tail_p2p::Size>(msg_buffer.size()));
          memcpy(slot, &sm, msg_buffer.size());
          sender.send();
        }
      }
      for (auto [idx, receiver] : hipony::enumerate(receivers)) {
        if (auto polled = receiver.poll()) {
          auto& sm = *reinterpret_cast<SignedMessage const*>(polled->msg());
          reqs.done(idx, Requests::Measure{sm.local_sign, sm.remote_verify});
          done++;
        }
      }
      for (auto& sender : senders) {
        sender.tick();
      }
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  } else {
    // Slave: verify + ack
    while (done < pings) {
      for (auto [idx, receiver] : hipony::enumerate(receivers)) {
        if (auto polled = receiver.poll()) {
          auto& sm1 = *reinterpret_cast<SignedMessage const*>(polled->msg());
          auto const verify_start = std::chrono::steady_clock::now();
          sm1.verify(msg_size, pony, path, p2p.remote_ids[idx]);
          auto const verify_end = std::chrono::steady_clock::now();
          auto& sender = senders[idx];
          auto& sm2 = *reinterpret_cast<SignedMessage*>(sender.getSlot(
              static_cast<tail_p2p::Size>(SignedMessage::pong_size())));
          sm2.local_sign = sm1.local_sign;
          sm2.remote_verify = verify_end - verify_start;
          sender.send();
          done++;
        }
      }
      for (auto& sender : senders) {
        sender.tick();
      }
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  }
  return false;
}

int main(int argc, char* argv[]) {
  fmt::print("WARNING: ACK ESTIMATION IS HARDCODED TO 1us!!!\n");
  fmt::print("Build Time: {}\n", BINARY_BUILD_TIME);

  lyra::cli cli;
  bool get_help = false;
  int local_id;
  size_t pings = 1 << 16;
  tail_p2p::Size msg_size = units::bytes(8);
  bool test_slow_path = false;
  int core_id = -1;
  size_t ingress_distance_ns = 15000;
  size_t timeout_s = 15;

  std::vector<ProcId> signers;
  std::vector<ProcId> verifiers;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("-l")
                        .name("--local-id")
                        .help("ID of the present process"))
      .add_argument(lyra::opt(signers, "signers")
                        .required()
                        .name("-s")
                        .name("--signer")
                        .help("ID of one of the signers"))
      .add_argument(lyra::opt(verifiers, "verifiers")
                        .required()
                        .name("-v")
                        .name("--verifiers")
                        .help("ID of one of the verifiers"))
      .add_argument(
          lyra::opt(pings, "pings").name("-p").name("--pings").help("Pings"))
      .add_argument(lyra::opt(msg_size, "msg_size")
                        .name("-s")
                        .name("--msg_size")
                        .help("Size of messages"))
      .add_argument(lyra::opt(test_slow_path)
                        .name("-S")
                        .name("--test-slow-path")
                        .help("Benchmark the slow path"))
      .add_argument(lyra::opt(core_id, "core_id")
                        .name("--core-pinning")
                        .help("Pin main thread to a particular core"))
      .add_argument(
          lyra::opt(ingress_distance_ns, "distance between two requests in ns")
              .name("-d")
              .name("--ingress_distance")
              .help("Average distance between two requests in ns"))
      .add_argument(lyra::opt(timeout_s, "timeout")
                        .name("-t")
                        .name("--timeout")
                        .help("Seconds before stopping the experiment"));

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

  for (auto const& signer : signers) {
    if (std::find(verifiers.begin(), verifiers.end(), signer) !=
        verifiers.end()) {
      throw std::runtime_error(
          fmt::format("{} is both a signer and verifier!", signer));
    }
  }
  if (std::find(verifiers.begin(), verifiers.end(), local_id) ==
          verifiers.end() &&
      std::find(signers.begin(), signers.end(), local_id) == signers.end()) {
    throw std::runtime_error(fmt::format(
        "local id {} is neither a signer nor a verifier!", local_id));
  }
  if (signers.size() != 1 && verifiers.size() != 1) {
    throw std::runtime_error("cannot scale both signers and verifiers!");
  }
  auto role =
      std::find(verifiers.begin(), verifiers.end(), local_id) != verifiers.end()
          ? Verifier
          : Signer;

  std::vector<ProcId> remote_ids;
  for (auto const verifier : verifiers) {
    if (verifier != local_id) {
      remote_ids.push_back(verifier);
    }
  }
  for (auto const signer : signers) {
    if (signer != local_id) {
      remote_ids.push_back(signer);
    }
  }

  Path const path = test_slow_path ? Slow : Fast;

  auto& store = dory::memstore::MemoryStore::getInstance();

  size_t const max_outstanding = pony::SkCtxs * pony::SignaturesPerSecretKey;
  std::chrono::nanoseconds const ingress_distance{ingress_distance_ns};
  std::chrono::seconds const timeout(timeout_s);

  Pony pony(local_id, false);
  pin_main(core_id);
  P2p p2p(local_id, remote_ids, SignedMessage::size(msg_size), max_outstanding);

  size_t dummy_msg = 0;

  std::unique_ptr<Requests> requests = std::make_unique<ConstantRequests>(
      pony, verifiers, max_outstanding, ingress_distance);

  std::string run_barrier{""};
  while (!pony.replenished_sks())
    ;
  for (auto const remote_id : remote_ids) {
    while (!pony.replenished_pks(remote_id))
      ;
  }

  auto start = Clock::now();
  auto const timed_out = run_test(role, dummy_msg, pings, msg_size, p2p, pony,
                                  *requests, path, timeout);
  auto stop = Clock::now();

  auto const& msrs = requests->msrs;

  std::chrono::nanoseconds duration = stop - start;

  // Print the measurements
  if (local_id == 1) {
    if (timed_out) {
      fmt::print(
          "[Size={}/Path={}, Pings={}, Signers={}, Verifiers={}] Timed-out\n",
          msg_size, to_string(path), pings, signers.size(), verifiers.size());
      fmt::print("###DONE###\n");
      return 1;
    }

    fmt::print(
        "[Size={}/Path={}, Pings={}, Signers={}, Verifiers={}] "
        "latency: {} (buffer: {}, signing: {}, verifying: {}, network+remote "
        "buffer: "
        "{}), throughput: {} sig/s\n",
        msg_size, to_string(path), pings, signers.size(), verifiers.size(),
        msrs.overall_profiling.percentile(50),
        msrs.in_buffer_profiling.percentile(50),
        msrs.local_sign_profiling.percentile(50),
        msrs.remote_verify_profiling.percentile(50),
        msrs.network_profiling.percentile(50),
        pings * 1000 * 1000 * 1000 / duration.count());

    fmt::print("\nOne-way\n");
    msrs.overall_profiling.report();

    fmt::print("\nBuffer\n");
    msrs.in_buffer_profiling.report();

    fmt::print("\nSign\n");
    msrs.local_sign_profiling.report();

    fmt::print("\nVerify\n");
    msrs.remote_verify_profiling.report();

    fmt::print("\nNetwork+remote buffer\n");
    msrs.network_profiling.report();
  }
  fmt::print("###DONE###\n");

  return 0;
}

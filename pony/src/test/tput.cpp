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
  P2p(ProcId const local_id, size_t const msg_size, size_t const slots)
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

    tail_p2p::SenderBuilder sender_builder(*cb, local_id, remote_id, "main",
                                           slots, msg_size);
    tail_p2p::ReceiverBuilder receiver_builder(*cb, local_id, remote_id, "main",
                                               slots, msg_size);
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

class Requests {
 public:
  Requests(Pony& pony, size_t const max_outstanding)
      : pony{pony}, max_outstanding{max_outstanding} {
    outstanding.resize(max_outstanding);
    outstanding.resize(0);
  }

  virtual bool poll() = 0;

  struct Measure {
    std::chrono::nanoseconds local_sign;
    std::chrono::nanoseconds remote_verify;
  };
  void done(Measure const& msr) {
    static constexpr std::chrono::nanoseconds ack{1000};
    auto const ponged_at = std::chrono::steady_clock::now();
    auto const& completed = outstanding.front();
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
    outstanding.pop_front();
  }

  struct Request {
    std::chrono::steady_clock::time_point received_at;
    std::chrono::steady_clock::time_point polled_at;
  };
  std::deque<Request> outstanding;

  Measurements msrs;
  static constexpr std::chrono::microseconds DropAfter =
      std::chrono::microseconds(200);

  Pony& pony;
  size_t const max_outstanding;
};

// Requests that arrive
class AutoRequests : public Requests {
 public:
  AutoRequests(Pony& pony, size_t const max_outstanding)
      : Requests{pony, max_outstanding} {}

  bool poll() override {
    if (outstanding.size() >= max_outstanding) {
      return false;
    }
    auto const now = std::chrono::steady_clock::now();
    outstanding.emplace_back(Request{now, now});
    return true;
  }
};

struct ConstantRequests : public Requests {
 public:
  ConstantRequests(Pony& pony, size_t const max_outstanding,
                   std::chrono::nanoseconds const distance)
      : Requests{pony, max_outstanding}, distance{distance} {}

  bool poll() override {
    if (outstanding.size() >= max_outstanding) {
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
    outstanding.emplace_back(Request{received, now});
    last_received = received;
    return true;
  }

  std::chrono::nanoseconds const distance;
  std::optional<std::chrono::steady_clock::time_point> last_received;
  std::optional<std::chrono::steady_clock::time_point> to_poll;
};

struct ExponentialRequests : public Requests {
 public:
  ExponentialRequests(Pony& pony, size_t const max_outstanding,
                      std::chrono::nanoseconds const distance)
      : Requests{pony, max_outstanding},
        exp{1. / static_cast<double>(distance.count())} {}

  bool poll() override {
    if (outstanding.size() >= max_outstanding) {
      while (!pony.replenished_sks()) {
      }
      return false;
    }
    auto const now = std::chrono::steady_clock::now();
    if (!to_poll) {
      auto const distance =
          std::chrono::nanoseconds(static_cast<size_t>(exp(gen)));
      to_poll = (last_received && now - (*last_received + distance) < DropAfter)
                    ? *last_received + distance
                    : now;
    }
    if (*to_poll > now) {
      return false;
    }
    outstanding.emplace_back(Request{*to_poll, now});
    last_received = *to_poll;
    to_poll.reset();
    return true;
  }

  std::mt19937 gen{std::random_device()()};
  std::exponential_distribution<> exp;
  std::optional<std::chrono::steady_clock::time_point> last_received;
  std::optional<std::chrono::steady_clock::time_point> to_poll;
};

static bool run_test(size_t& dummy_msg, size_t const pings,
                     size_t const msg_size, P2p& p2p, Pony& pony,
                     Requests& reqs, Path const path,
                     std::chrono::seconds const timeout) {
  auto& sender = *p2p.sender;
  auto& receiver = *p2p.receiver;
  size_t done = 0;
  auto const start = std::chrono::steady_clock::now();

  if (p2p.local_id == 1) {
    // Master: signer + measurer
    while (done < pings) {
      if (reqs.poll()) {
        auto& sm = *reinterpret_cast<SignedMessage*>(sender.getSlot(
            static_cast<tail_p2p::Size>(SignedMessage::size(msg_size))));
        sm.local_sign = sm.fill(dummy_msg++, msg_size, pony);
        sender.send();
      }
      if (auto polled = receiver.poll()) {
        auto& sm = *reinterpret_cast<SignedMessage const*>(polled->msg());
        reqs.done(Requests::Measure{sm.local_sign, sm.remote_verify});
        done++;
      }
      sender.tick();
      if (std::chrono::steady_clock::now() - start > timeout) {
        return true;
      }
    }
  } else {
    // Slave: verify + ack
    while (done < pings) {
      if (auto polled = receiver.poll()) {
        auto& sm1 = *reinterpret_cast<SignedMessage const*>(polled->msg());
        auto const verify_start = std::chrono::steady_clock::now();
        sm1.verify(msg_size, pony, path, p2p.remote_id);
        auto const verify_end = std::chrono::steady_clock::now();
        auto& sm2 = *reinterpret_cast<SignedMessage*>(sender.getSlot(
            static_cast<tail_p2p::Size>(SignedMessage::pong_size())));
        sm2.local_sign = sm1.local_sign;
        sm2.remote_verify = verify_end - verify_start;
        sender.send();
        done++;
      }
      sender.tick();
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
  std::string scheme;
  std::string ingress;
  size_t ingress_distance_ns = 15000;
  size_t timeout_s = 15;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(scheme, "pony,sodium,dalek")
                        .required()
                        .choices("pony", "sodium", "dalek")
                        .name("--scheme")
                        .help("Which crypto scheme to use"))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("-l")
                        .name("--local-id")
                        .help("ID of the present process"))
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
      .add_argument(lyra::opt(ingress, "auto,constant,exponential")
                        .required()
                        .choices("auto", "constant", "exponential")
                        .name("-i")
                        .name("--ingress")
                        .help("When to issue new signatures"))
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

  Path const path = test_slow_path ? Slow : Fast;

  auto& store = dory::memstore::MemoryStore::getInstance();
  ProcId const remote_id = local_id == 1 ? 2 : 1;

  size_t const max_outstanding =
      scheme == "pony" ? pony::SkCtxs * pony::SignaturesPerSecretKey : 128;
  std::chrono::nanoseconds const ingress_distance{ingress_distance_ns};
  std::chrono::seconds const timeout(timeout_s);

  fmt::print("Used crypto scheme: {}\n", scheme);

  if (scheme != "pony") {
    throw std::runtime_error("The only supported scheme is pony");
  }

  Pony pony(local_id, false);
  pin_main(core_id);
  P2p p2p(local_id, SignedMessage::size(msg_size), max_outstanding);

  size_t dummy_msg = 0;

  std::unique_ptr<Requests> requests;
  if (ingress == "auto") {
    requests = std::make_unique<AutoRequests>(pony, max_outstanding);
  } else if (ingress == "constant") {
    requests = std::make_unique<ConstantRequests>(pony, max_outstanding,
                                                  ingress_distance);
  } else if (ingress == "exponential") {
    requests = std::make_unique<ExponentialRequests>(pony, max_outstanding,
                                                     ingress_distance);
  } else {
    throw std::runtime_error("Unsupported ingress");
  }

  std::string run_barrier{""};
  while (!pony.replenished_sks() || !pony.replenished_pks(remote_id))
    ;
  if (local_id == 1) {
    // Master
    store.set("run_barrier_1", "1");
    while (!store.get("run_barrier_2", run_barrier))
      ;
  } else {
    // Slave
    while (!store.get("run_barrier_1", run_barrier))
      ;
    store.set("run_barrier_2", "1");
  }

  auto start = Clock::now();
  auto const timed_out =
      run_test(dummy_msg, pings, msg_size, p2p, pony, *requests, path, timeout);
  auto stop = Clock::now();

  auto const& msrs = requests->msrs;

  std::chrono::nanoseconds duration = stop - start;

  // Print the measurements
  if (local_id == 1) {
    if (timed_out) {
      fmt::print("[Size={}/Path={}, Pings={}] Timed-out\n", msg_size,
                 to_string(path), pings);
      fmt::print("###DONE###\n");
      return 1;
    }

    fmt::print(
        "[Size={}/Path={}, Pings={}] "
        "latency: {} (buffer: {}, signing: {}, verifying: {}, network+remote "
        "buffer: "
        "{}), throughput: {} sig/s\n",
        msg_size, to_string(path), pings, msrs.overall_profiling.percentile(50),
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

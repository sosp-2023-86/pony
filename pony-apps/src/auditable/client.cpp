#include <array>
#include <chrono>
#include <deque>
#include <memory>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include <fmt/core.h>
#include <fmt/ranges.h>
#include <lyra/lyra.hpp>

#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>

#include <dory/shared/dynamic-bitset.hpp>
#include <dory/shared/logger.hpp>
#include <dory/shared/pinning.hpp>
#include <dory/shared/units.hpp>

#include <dory/shared/latency.hpp>
#include <dory/ubft/rpc/client.hpp>
#include <dory/ubft/types.hpp>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>
#include <dory/pony/export/pony.hpp>

#include "common.hpp"

#include "app/flip.hpp"
#include "app/herd.hpp"
#include "app/liquibook.hpp"
#include "app/memc.hpp"
#include "app/redis.hpp"

template <typename Duration>
static void busy_sleep(Duration duration) {
  auto const start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < duration)
    ;
}

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

static auto main_logger = dory::std_out_logger("Main");

int main(int argc, char *argv[]) {
  //// Parse Arguments ////
  lyra::cli cli;
  bool get_help = false;
  int core_id = -1;
  dory::ubft::ProcId local_id;
  dory::ubft::ProcId server_id;
  std::vector<dory::ubft::ProcId> client_ids;
  std::string dev_name;
  size_t window = 1;
  size_t requests_to_send = 10000;
  std::string scheme_str;
  std::string app;
  std::string app_config;
  bool check_flip = false;
  bool dump_all_percentiles = false;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(core_id, "core_id")
                        .name("--core-pinning")
                        .help("Pin main thread to a particular core"))
      .add_argument(lyra::opt(dev_name, "name")
                        .required()
                        .name("--dev")
                        .help("Name of the Infiniband device"))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("--local-id")
                        .help("ID of the present process"))
      .add_argument(lyra::opt(server_id, "id")
                        .required()
                        .name("--server-id")
                        .help("ID of server"))
      .add_argument(lyra::opt(client_ids, "id")
                        .required()
                        .name("--client-id")
                        .help("IDs of the other clients"))
      .add_argument(lyra::opt(scheme_str, "none,pony,sodium,dalek")
                        .required()
                        .choices("none", "pony", "sodium", "dalek")
                        .name("--scheme")
                        .help("Which crypto scheme to use"))
      .add_argument(lyra::opt(dump_all_percentiles)
                        .name("--dump-percentiles")
                        .help("Dump all percentiles"))
      .add_argument(lyra::opt(app, "application")
                        .required()
                        .name("-a")
                        .name("--application")
                        .choices("flip", "memc", "redis", "herd",
                                 "liquibook")("Which application to run"))
      .add_argument(lyra::opt(app_config, "app_config")
                        .name("-c")
                        .name("--app-config")
                        .help("App specific config"))
      .add_argument(lyra::opt(window, "window")
                        .name("-w")
                        .name("--window")
                        .help("Clients' window"))
      .add_argument(lyra::opt(requests_to_send, "requests_to_send")
                        .name("-r")
                        .name("--requests_to_send")
                        .help("Requests to send"))
      .add_argument(lyra::opt(check_flip)
                        .name("--check")
                        .help("Check that the responses in the flip "
                              "application are the inverse of the requests"));

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

  //// Setup RDMA ////
  LOGGER_INFO(main_logger, "Opening RDMA device ...");
  bool device_found = false;

  dory::ctrl::Devices d;
  dory::ctrl::OpenDevice open_device;
  for (auto &dev : d.list()) {
    if (dev_name == std::string(dev.name())) {
      open_device = std::move(dev);
      device_found = true;
      break;
    }
  }

  if (!device_found) {
    LOGGER_ERROR(main_logger,
                 "Could not find the RDMA device {}. Run `ibv_devices` to get "
                 "the device names.",
                 dev_name);
    return 1;
  }

  LOGGER_INFO(main_logger, "Device: {} / {}, {}, {}", open_device.name(),
              open_device.devName(),
              dory::ctrl::OpenDevice::typeStr(open_device.nodeType()),
              dory::ctrl::OpenDevice::typeStr(open_device.transportType()));

  size_t binding_port = 0;
  LOGGER_INFO(main_logger, "Binding to port {} of opened device {}",
              binding_port, open_device.name());
  dory::ctrl::ResolvedPort resolved_port(open_device);
  auto binded = resolved_port.bindTo(binding_port);
  if (!binded) {
    throw std::runtime_error("Couldn't bind the device.");
  }
  LOGGER_INFO(main_logger, "Binded successfully (port_id, port_lid) = ({}, {})",
              +resolved_port.portId(), +resolved_port.portLid());

  LOGGER_INFO(main_logger, "Configuring the control block");
  dory::ctrl::ControlBlock cb(resolved_port);

  //// Create Memory Regions and QPs ////
  cb.registerPd("standard");
  cb.registerCq("unused");

  //// Application logic ////
  LOGGER_INFO(main_logger, "Running `{}`", app);
  std::unique_ptr<Application> chosen_app;
  if (app == "flip") {
    chosen_app = std::make_unique<Flip>(false, app_config);
  } else if (app == "memc") {
    chosen_app = std::make_unique<Memc>(false, app_config);
  } else if (app == "redis") {
    chosen_app = std::make_unique<Redis>(false, app_config);
  } else if (app == "liquibook") {
    auto liquibook_app = std::make_unique<Liquibook>(false, app_config);
    liquibook_app->setClientId(local_id);
    chosen_app = std::move(liquibook_app);
  } else if (app == "herd") {
    chosen_app = std::make_unique<Herd>(false, app_config);
  } else {
    throw std::runtime_error("Unknown application");
  }

  size_t sig_size = 0;
  auto &store = dory::memstore::MemoryStore::getInstance();

  std::unique_ptr<dory::crypto::asymmetric::AsymmetricCrypto> eddsa_crypto;
  std::unordered_map<dory::ubft::ProcId,
                     dory::crypto::asymmetric::AsymmetricCrypto::PublicKey>
      eddsa_pks;

  std::unique_ptr<dory::pony::PonyLib> pony_crypto;

  auto scheme = get_scheme(scheme_str);

  // Setup the crypto module and share all public keys
  if (scheme_str == "pony") {
    pony_crypto = std::make_unique<dory::pony::PonyLib>(local_id, false);
    sig_size = sizeof(dory::pony::Signature);
  } else if (scheme_str == "sodium" || scheme_str == "dalek") {
    LOGGER_INFO(main_logger, "Auditability using {}", scheme_str);
    if (scheme_str == "dalek") {
      eddsa_crypto =
          std::make_unique<dory::crypto::asymmetric::DalekAsymmetricCrypto>(
              true);
      bool avx =
          dynamic_cast<dory::crypto::asymmetric::DalekAsymmetricCrypto *>(
              eddsa_crypto.get())
              ->avx();
      fmt::print("Dalek {} AVX\n", avx ? "uses" : "does not use");
    } else {
      eddsa_crypto =
          std::make_unique<dory::crypto::asymmetric::SodiumAsymmetricCrypto>(
              true);
    }
    sig_size = sizeof(dory::crypto::asymmetric::AsymmetricCrypto::Signature);

    eddsa_crypto->publishPublicKey(fmt::format("p{}-pk", local_id));
    store.barrier("public_keys_announced", client_ids.size() + 1);

    for (auto cid : client_ids) {
      if (cid == local_id) {
        eddsa_pks.insert(
            {cid, eddsa_crypto->getPublicKey(fmt::format("p{}-pk", cid))});
      }
    }
    store.barrier("public_keys_cached", client_ids.size() + 1);
  } else {
    LOGGER_INFO(main_logger, "No auditability");
  }

  if (scheme_str != "none") {
    LOGGER_INFO(main_logger, "Auditability using {}, signature size: {}B",
                scheme_str, sig_size);
  }

  // WORKAROUND: Wait for the server to announce it PID
  std::this_thread::sleep_for(std::chrono::seconds(10));

  pin_main(core_id);

  size_t data_offset = roundUp(sig_size, 16);
  size_t const max_req_size = data_offset + chosen_app->maxRequestSize();
  size_t const max_resp_size = data_offset + chosen_app->maxResponseSize();

  //// Configure the RPC to bypass the crypto and thread pool used by uBFT ////
  dory::ubft::Crypto crypto_bypass(local_id, {}, true);
  dory::ubft::TailThreadPool thread_pool_bypass("ubft-pool", 0);
  dory::ubft::rpc::Client rpc_client(crypto_bypass, thread_pool_bypass, cb,
                                     local_id, {server_id}, "app", window,
                                     max_req_size, max_resp_size);
  rpc_client.toggleSlowPath(false);

  dory::ubft::Buffer response(max_resp_size);

  dory::LatencyProfiler latency_profiler(0);
  std::deque<std::chrono::steady_clock::time_point> request_posted_at;
  std::chrono::steady_clock::time_point proposal_time;

  size_t fulfilled_requests = 0;
  size_t outstanding_requests = 0;

  // Used with the flip application to check the results
  std::queue<std::vector<uint8_t>> check;

  while (fulfilled_requests < requests_to_send) {
    rpc_client.tick();
    while (auto const polled = rpc_client.poll(response.data())) {
      latency_profiler.addMeasurement(std::chrono::steady_clock::now() -
                                      request_posted_at.front());
      request_posted_at.pop_front();
      response.resize(*polled);

      if (check_flip) {
        auto &original_request = check.front();

        if (*polled != original_request.size()) {
          throw std::runtime_error("Response size was not the expected one!");
        }

        size_t i = original_request.size() - 1;
        for (auto c = response.cbegin(); c != response.cend(); i--, c++) {
          if (original_request[i] != *c) {
            throw std::runtime_error("Response was not the expected one!");
          }
        }
        check.pop();
      }

      busy_sleep(std::chrono::microseconds(50));

      fulfilled_requests++;
      outstanding_requests--;
    }
    while (outstanding_requests < window &&
           fulfilled_requests + outstanding_requests < requests_to_send) {
      auto &request = chosen_app->randomRequest();

      if (check_flip) {
        check.push(request);
      }

      auto slot = rpc_client.getSlot(data_offset + request.size());
      if (!slot) {
        throw std::logic_error("Ran out of RPC slots!");
      }

      auto *slot_ptr = *slot;

      std::copy(request.begin(), request.end(), slot_ptr + data_offset);

      request_posted_at.push_back(std::chrono::steady_clock::now());

      switch (scheme) {
        case Scheme::None: {
        }; break;
        case Scheme::Dalek:
        case Scheme::Sodium: {
          auto sig_view = eddsa_crypto->signatureView(slot_ptr);
          eddsa_crypto->sign(sig_view, slot_ptr + data_offset, request.size());
        }; break;
        case Scheme::Pony: {
          auto *sig_view = reinterpret_cast<dory::pony::Signature *>(slot_ptr);
          pony_crypto->sign(*sig_view, slot_ptr + data_offset, request.size());
        }; break;
        default:
          throw std::logic_error("Unknown crypto variant");
      }

      outstanding_requests++;
      rpc_client.post();
    }
  }
  latency_profiler.report(dump_all_percentiles);

  fmt::print("###DONE###\n");

  return 0;
}

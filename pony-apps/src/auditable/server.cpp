#include <chrono>
#include <unordered_map>
#include <vector>

#include <lyra/lyra.hpp>

#include <fmt/core.h>
#include <fmt/ranges.h>

#include <dory/ctrl/block.hpp>
#include <dory/ctrl/device.hpp>

#include <dory/shared/logger.hpp>
#include <dory/shared/pinning.hpp>
#include <dory/shared/units.hpp>

#include <dory/ubft/rpc/server.hpp>
#include <dory/ubft/types.hpp>

#include <dory/crypto/asymmetric/switchable-crypto.hpp>
#include <dory/pony/export/pony.hpp>

#include "common.hpp"

#include "app/flip.hpp"
#include "app/herd.hpp"
#include "app/liquibook.hpp"
#include "app/memc.hpp"
#include "app/redis.hpp"

static auto main_logger = dory::std_out_logger("Init");

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

int main(int argc, char *argv[]) {
  //// Parse Arguments ////
  lyra::cli cli;
  bool get_help = false;
  int core_id = -1;
  dory::ubft::ProcId local_id;
  std::vector<dory::ubft::ProcId> client_ids;
  std::string dev_name;
  size_t window = 1;
  std::string scheme_str;
  std::string app;
  std::string app_config;

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
      .add_argument(lyra::opt(client_ids, "ids")
                        .required()
                        .name("--client-id")
                        .help("IDs of the other clients"))
      .add_argument(lyra::opt(scheme_str, "none,pony,sodium,dalek")
                        .required()
                        .choices("none", "pony", "sodium", "dalek")
                        .name("--scheme")
                        .help("Which crypto scheme to use"))
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
                        .help("Clients' window"));

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
  dory::ubft::ProcId const min_client_id = 2;
  dory::ubft::ProcId const max_client_id = 32;
  size_t const server_window = window;
  auto const max_connections =
      static_cast<size_t>(max_client_id - min_client_id + 1);

  LOGGER_INFO(main_logger, "Running `{}`", app);
  std::unique_ptr<Application> chosen_app;
  if (app == "flip") {
    chosen_app = std::make_unique<Flip>(true, app_config);
  } else if (app == "memc") {
    chosen_app = std::make_unique<Memc>(true, app_config);
  } else if (app == "redis") {
    chosen_app = std::make_unique<Redis>(true, app_config);
  } else if (app == "liquibook") {
    chosen_app = std::make_unique<Liquibook>(true, app_config);
  } else if (app == "herd") {
    chosen_app = std::make_unique<Herd>(true, app_config);
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
    store.barrier("public_keys_announced", 1 + client_ids.size());

    for (auto const remote_id : client_ids) {
      eddsa_pks.insert({remote_id, eddsa_crypto->getPublicKey(
                                       fmt::format("p{}-pk", remote_id))});
    }
    store.barrier("public_keys_cached", 1 + client_ids.size());
  } else {
    LOGGER_INFO(main_logger, "No auditability");
  }

  if (scheme_str != "none") {
    LOGGER_INFO(main_logger, "Auditability using {}, signature size: {}B",
                scheme_str, sig_size);
  }

  // // WORKAROUND: Wait for the server to announce it PID
  // std::this_thread::sleep_for(std::chrono::seconds(10));

  pin_main(core_id);

  size_t data_offset = roundUp(sig_size, 16);
  size_t const max_req_size = data_offset + chosen_app->maxRequestSize();
  size_t const max_resp_size = data_offset + chosen_app->maxResponseSize();

  std::vector<std::vector<uint8_t>> logs;

  size_t log_sz = 300000;
  size_t log_idx = 0;
  if (scheme_str != "none") {
    LOGGER_INFO(main_logger, "Using a log of {} elements", log_sz);
    logs.resize(log_sz);
    for (auto &entry : logs) {
      entry.resize(max_req_size);

      // Trully allocate the memory (to avoid page faults)
      std::fill(entry.begin(), entry.end(), 0);
    }
    LOGGER_INFO(main_logger, "Log ready", log_sz);
  }

  //// Configure the RPC to bypass the crypto and thread pool used by uBFT ////
  dory::ubft::Crypto crypto_bypass(local_id, {}, true);
  dory::ubft::TailThreadPool thread_pool_bypass("ubft-pool", 0);
  dory::ubft::rpc::Server rpc_server(
      crypto_bypass, thread_pool_bypass, cb, local_id, "app", min_client_id,
      max_client_id, window, max_req_size, max_resp_size, max_connections,
      server_window, {local_id});
  rpc_server.toggleOptimism(true);

  std::vector<uint8_t> response;
  response.reserve(max_resp_size);

  while (true) {
    rpc_server.tick();
    if (auto polled_received = rpc_server.pollReceived()) {
      auto &request = polled_received->get();

      size_t msg_size = request.size() - data_offset;
      auto const *msg = request.payload() + data_offset;

      switch (scheme) {
        case Scheme::None: {
        }; break;
        case Scheme::Dalek:
        case Scheme::Sodium: {
          using Signature =
              dory::crypto::asymmetric::AsymmetricCrypto::Signature;
          Signature const *sig =
              reinterpret_cast<Signature const *>(request.payload());

          if (!eddsa_crypto->verify(*sig, msg, msg_size,
                                    eddsa_pks[request.clientId()])) {
            throw std::runtime_error("Verification failed");
          }

          // if (log_idx > log_sz) {
          //   throw std::runtime_error("Run out of logs!");
          // }

          // auto &logged = logs[log_idx++];
          // std::memcpy(logged.data(), request.payload(), request.size());
          // logged.resize(request.size());

        }; break;
        case Scheme::Pony: {
          auto const *sig_view =
              reinterpret_cast<dory::pony::Signature const *>(
                  request.payload());
          if (!pony_crypto->verify(*sig_view, msg, msg_size,
                                   request.clientId())) {
            throw std::runtime_error("Verification failed");
          }

          if (log_idx > log_sz) {
            throw std::runtime_error("Run out of logs!");
          }

          auto &logged = logs[log_idx++];
          std::memcpy(logged.data(), request.payload(), request.size());
          logged.resize(request.size());

        }; break;
        default:
          throw std::logic_error("Unknown crypto variant");
      }

      // Decapsulate the signature
      chosen_app->execute(msg, msg_size, response);

      rpc_server.executed(request.clientId(), request.id(), response.data(),
                          response.size());
    }
  }

  return 0;
}

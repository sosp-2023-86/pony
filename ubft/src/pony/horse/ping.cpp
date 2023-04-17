#include <chrono>
#include <iostream>
#include <memory>

#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include <dory/memstore/store.hpp>
#include <dory/shared/branching.hpp>
#include <dory/shared/types.hpp>

#include "../../tail-p2p/receiver-builder.hpp"
#include "../../tail-p2p/sender-builder.hpp"
#include "common.hpp"

using namespace dory::ubft;
using namespace pony;
size_t constexpr MessageSize = 128;
using SignedMessage = horse::SignedMessage<MessageSize>;

horse::PublicKey receive_pk(tail_p2p::Receiver&, tail_p2p::Sender&);
horse::PublicKey receive_pk(tail_p2p::Receiver& pk_receiver,
                            tail_p2p::Sender& some_sender) {
  horse::PublicKey::Serialized serialized_pk;
  // fmt::print("Polling pk...\n");
  while (!pk_receiver.poll(&serialized_pk)) {
    some_sender.tick();
  }
  // fmt::print("Received pk!\n");
  return serialized_pk;
}

void receive_sm(tail_p2p::Receiver&, horse::PublicKey&, tail_p2p::Sender&);
void receive_sm(tail_p2p::Receiver& sm_receiver, horse::PublicKey& pk,
                tail_p2p::Sender& sm_sender) {
  SignedMessage sm;
  while (!sm_receiver.poll(&sm)) {
    sm_sender.tick();
  }
  auto const good = pk.verify(sm);
  if (unlikely(!good)) {
    fmt::print("FAILURE!\n");
    exit(1);
  }
}

int main(int argc, char* argv[]) {
  //// Parse Arguments ////
  lyra::cli cli;
  bool get_help = false;
  int local_id;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("-l")
                        .name("--local-id")
                        .choices(1, 2)
                        .help("ID of the present process"));
  auto result = cli.parse({argc, argv});

  auto const remote_id = 3 - local_id;

  if (get_help) {
    std::cout << cli;
    return 0;
  }

  //// Setup RDMA ////
  auto open_device = std::move(dory::ctrl::Devices().list()[0]);
  dory::ctrl::ResolvedPort resolved_port(open_device);
  if (!resolved_port.bindTo(0)) {
    throw std::runtime_error("Couldn't bind the device.");
  }
  dory::ctrl::ControlBlock cb(resolved_port);
  cb.registerPd("standard");
  cb.registerCq("unused");

  // Establish connections
  auto& store = dory::memstore::MemoryStore::getInstance();
  tail_p2p::SenderBuilder pk_sender_builder(
      cb, local_id, remote_id, "pk", 1, sizeof(horse::PublicKey::Serialized));
  tail_p2p::ReceiverBuilder pk_receiver_builder(
      cb, local_id, remote_id, "pk", 1, sizeof(horse::PublicKey::Serialized));
  tail_p2p::SenderBuilder sm_sender_builder(cb, local_id, remote_id, "sm", 1,
                                            sizeof(SignedMessage));
  tail_p2p::ReceiverBuilder sm_receiver_builder(cb, local_id, remote_id, "sm",
                                                1, sizeof(SignedMessage));
  tail_p2p::SenderBuilder sync_sender_builder(cb, local_id, remote_id, "sync",
                                              1, 0);
  tail_p2p::ReceiverBuilder sync_receiver_builder(cb, local_id, remote_id,
                                                  "sync", 1, 0);

  pk_sender_builder.announceQps();
  pk_receiver_builder.announceQps();
  sm_sender_builder.announceQps();
  sm_receiver_builder.announceQps();
  sync_sender_builder.announceQps();
  sync_receiver_builder.announceQps();
  store.barrier("annonunced", 2);
  pk_sender_builder.connectQps();
  pk_receiver_builder.connectQps();
  sm_sender_builder.connectQps();
  sm_receiver_builder.connectQps();
  sync_sender_builder.connectQps();
  sync_receiver_builder.connectQps();
  store.barrier("connected", 2);
  auto pk_sender = pk_sender_builder.build();
  auto pk_receiver = pk_receiver_builder.build();
  auto sm_sender = sm_sender_builder.build();
  auto sm_receiver = sm_receiver_builder.build();
  auto sync_sender = sync_sender_builder.build();
  auto sync_receiver = sync_receiver_builder.build();
  store.barrier("inited", 2);

  // Generate keys
  horse::RandomBytesEngine rbe;
  fmt::print("Private key size: {}B (t={}, d={})\n", sizeof(horse::PrivateKey),
             horse::t, horse::d);
  fmt::print("Public key size: {}B\n", sizeof(horse::PublicKey));
  fmt::print("Serialized public key size: {}B\n",
             sizeof(horse::PublicKey::Serialized));
  fmt::print("Signature size: {}B ({} secrets)\n", sizeof(horse::Signature),
             horse::secrets_per_signature);

  using Clock = std::chrono::steady_clock;
  size_t const runs = 16;
  size_t const pings = 2048;

  for (size_t run = 0; run < runs; run++) {
    sm_sender.tick();

    // Message initialization
    SignedMessage sm;
    for (size_t i = 0; i != MessageSize; i++) {
      sm.message[i] = static_cast<uint8_t>(i);
    }

    // PK/SK generation + emission
    auto const key_generation_start = std::chrono::steady_clock::now();
    auto private_key = std::make_unique<horse::PrivateKey>(rbe);
    auto public_key = std::make_unique<horse::PublicKey>(*private_key);
    std::chrono::nanoseconds const key_generation(Clock::now() -
                                                  key_generation_start);
    fmt::print("Keys generated in {}\n", key_generation);

    // We sync the nodes so that the next measurement is meaningful.
    sync_sender.getSlot(0);
    sync_sender.send();
    sync_sender.tick();
    while (!sync_receiver.poll(nullptr)) {
      sync_sender.tick();
    }

    // We measure the time to send a pk.
    auto const pk_exchange_start = std::chrono::steady_clock::now();
    dory::Delayed<std::unique_ptr<horse::PublicKey>> delayed_remote_pk;
    if (local_id == 2) {
      delayed_remote_pk = std::make_unique<horse::PublicKey>(
          receive_pk(pk_receiver, sync_sender));
    }
    *reinterpret_cast<horse::PublicKey::Serialized*>(pk_sender.getSlot(
        sizeof(horse::PublicKey::Serialized))) = public_key->serialize();
    pk_sender.send();
    pk_sender.tick();
    // fmt::print("PK issued.\n");
    if (local_id == 1) {
      delayed_remote_pk = std::make_unique<horse::PublicKey>(
          receive_pk(pk_receiver, pk_sender));
    }
    auto& remote_pk = **delayed_remote_pk;
    std::chrono::nanoseconds const pk_exchange(Clock::now() -
                                               pk_exchange_start);

    if (local_id == 1) {
      fmt::print("Keys exchanged in {}, measured one-way latency: {}\n",
                 pk_exchange, pk_exchange / 2);
    }

    // We sync the nodes so that the next measurement is meaningful.
    sync_sender.getSlot(0);
    sync_sender.send();
    sync_sender.tick();
    while (!sync_receiver.poll(nullptr)) {
      pk_sender.tick();
      sync_sender.tick();
    }

    auto const ping_start = Clock::now();
    for (size_t i = 0; i < pings; i++) {
      // The 2nd node first receives a message before echoing it.
      if (local_id == 2) {
        receive_sm(sm_receiver, remote_pk, sm_sender);
      }

      // We increment the message.
      for (size_t i = 0; i < 8; i++) {
        if (++sm.message[i] != 0) {
          break;
        }
      }
      sm.signature = private_key->sign(sm.message.data(),
                                       sm.message.data() + sm.message.size());

      auto& sm_slot = *reinterpret_cast<SignedMessage*>(
          sm_sender.getSlot(sizeof(SignedMessage)));
      sm_slot = sm;
      sm_sender.send();

      if (local_id == 1) {
        receive_sm(sm_receiver, remote_pk, sm_sender);
      }
    }

    std::chrono::nanoseconds duration(Clock::now() - ping_start);
    if (local_id == 1) {
      fmt::print("[Size={}] {} pings in {}, measured one-way latency: {}\n",
                 MessageSize, pings, duration, duration / pings / 2);
    }
  }

  return 0;
}

#pragma once

#include <atomic>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>

#include "../types.hpp"
#include "../views.hpp"
#include "offload.hpp"

namespace dory::pony {

class SkContext {
 public:
  SkContext(std::unique_ptr<SkOffload>&& offload, size_t const max_acks,
            size_t const id)
      : offload{std::move(offload)},
        max_acks{max_acks},
        id{id},
        view{*this->offload} {}

  enum State {
    Free,
    ComputingKeysAndTree,
    ComputingEddsa,
    ToSend,
    Ready,
    WornOut,
    LAST_STATE = WornOut
  };
  using Profilers = std::array<LatencyProfiler, PkContext::LAST_STATE + 1>;

  void reset(Seed const& seed) {
    state = Free;
    eddsa_computed = false;
    acks = 0;
    signatures = 0;
    offload->reset(seed);
  }

  State state = Free;
  std::unique_ptr<SkOffload> offload;

  std::array<Hash, SignaturesPerSecretKey> nonces;
  std::atomic<bool> eddsa_computed = false;
  size_t acks = 0;
  size_t max_acks;

  size_t id;

  size_t signatures = 0;
  bool worn_out() const { return signatures == SignaturesPerSecretKey; }
  bool can_reuse_buffer() const { return acks == max_acks; }

  SkView view;

  std::array<std::chrono::steady_clock::time_point, LAST_STATE + 1> time_points;

  /**
   * @brief Move the context to another state and logs the time spent in the
   *        previous.
   *
   * @param state
   * @param profilers
   */
  void move_to(State const state, Profilers& profilers) {
    auto const previous_state = this->state;
    this->state = state;
    auto const now = time_points[state] = std::chrono::steady_clock::now();
    profilers[previous_state].addMeasurement(now - time_points[previous_state]);
  }

  friend std::ostream& operator<<(std::ostream& stream, SkContext const& ctx) {
    return stream << "SkContext[#" << ctx.id << ":" << to_string(ctx.state)
                  << "]";
  }

  inline static char const* to_string(State const state) {
    switch (state) {
      case SkContext::Free:
        return "FREE";
      case SkContext::ComputingKeysAndTree:
        return "COMPUTING_KEYS_AND_TREE";
      case SkContext::ComputingEddsa:
        return "COMPUTING_EDDSA";
      case SkContext::ToSend:
        return "TO_SEND";
      case SkContext::Ready:
        return "READY";
      case SkContext::WornOut:
        return "WORN_OUT";
      default:
        return "UNKNOWN";
    }
  }

  std::string to_string() {
    std::stringstream ss;
    ss << *this;
    return ss.str();
  }
};

}  // namespace dory::pony

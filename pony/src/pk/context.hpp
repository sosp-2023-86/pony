#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <memory>
#include <ostream>

#include "../types.hpp"
#include "../views.hpp"
#include "offload.hpp"

namespace dory::pony {

class PkContext {
 public:
  PkContext(ProcId const signer, std::unique_ptr<PkOffload>&& offload,
            size_t const id)
      : signer{signer},
        offload{std::move(offload)},
        id{id},
        view{*this->offload} {}

  enum State {
    Free,
    Armed,
    ComputingTree,
    VerifyingEddsa,
    Ready,
    Invalid,
    LAST_STATE = Invalid
  };
  using Profilers = std::array<LatencyProfiler, PkContext::LAST_STATE + 1>;

  void reset() {
    state = Free;
    eddsa_verified = false;
    verifications = 0;
    offload->reset();
  }

  State state = Free;
  ProcId signer;
  std::unique_ptr<PkOffload> offload;

  bool eddsa_valid;
  std::atomic<bool> eddsa_verified = false;

  size_t id;

  size_t verifications = 0;

  PkView view;

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

  friend std::ostream& operator<<(std::ostream& stream, PkContext const& ctx) {
    return stream << "PkContext[signer=" << ctx.signer << "#" << ctx.id << ":"
                  << to_string(ctx.state) << "]";
  }

  inline static char const* to_string(State const state) {
    switch (state) {
      case PkContext::Free:
        return "FREE";
      case PkContext::Armed:
        return "ARMED";
      case PkContext::ComputingTree:
        return "COMPUTING_TREE";
      case PkContext::VerifyingEddsa:
        return "VERIFYING_EDDSA";
      case PkContext::Ready:
        return "READY";
      case PkContext::Invalid:
        return "INVALID";
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

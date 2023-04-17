#pragma once

#include "internal/async-sender.hpp"
#include "internal/sync-sender.hpp"

namespace dory::pony::tail_p2p {
// Re-exports
using dory::pony::tail_p2p::internal::AsyncSender;
using dory::pony::tail_p2p::internal::SyncSender;
// Default is the async one.
using Sender = AsyncSender;
}  // namespace dory::pony::tail_p2p

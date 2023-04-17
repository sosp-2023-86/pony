#include <array>
#include <atomic>
#include <cstdint>
#include <memory>

#include <cuda_runtime.h>

#include "core.cuh"
#include "cuda-preallocate.cuh"
#include "cuda-raii.cuh"

// There is a potential compiler bug that messes up dc (relocatable device
// code), especially when using templates. The current workaround avoid
// compiling blake3 in separate files, i.e., blake3.cu is missing from CMake.
#include "blake3.inc"

// Helpers to decay std::arrays
template <typename T, size_t N>
__host__ __device__ T* decay(std::array<T, N>& a) {
  return reinterpret_cast<T*>(&a);
}
template <typename T, size_t N>
__host__ __device__ T const* decay(std::array<T, N> const& a) {
  return reinterpret_cast<T const*>(&a);
}

static inline __device__ void invalid_if_unequal(blake3::Hash const& a,
                                                 blake3::Hash const& b,
                                                 bool& valid) {
  using Comparable = uint64_t;
  auto* const ap = reinterpret_cast<Comparable const*>(&a);
  auto* const bp = reinterpret_cast<Comparable const*>(&b);
  for (size_t i = 0; i < sizeof(blake3::Hash) / sizeof(Comparable); i++) {
    if (ap[i] != bp[i]) {
      valid = false;
    }
  }
}

namespace dory::cuda {

size_t constexpr MaxConcurrency = 16;

static unsigned constexpr blocks(size_t const n) {
  return static_cast<unsigned>((n + ThreadsPerBlock - 1) / ThreadsPerBlock);
}

//////// SK

namespace dory::cuda::kernels {
__global__ void populate_sk(size_t const bytes, Seed const& seed,
                            void* const dst) {
  // Note: each call to aes256::encrypt generates aes::BlockSize random bytes.
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  size_t const offset = i * sizeof(blake3::Hash);
  if (offset >= bytes) {
    return;
  }
  blake3::hash<sizeof(Seed), true>(&seed,
                                   *(reinterpret_cast<blake3::Hash*>(dst) + i),
                                   static_cast<uint32_t>(i));
}
}  // namespace dory::cuda::kernels

void SecretKey::populate(UniqueCudaPtr<Seed> const& seed) {
  size_t constexpr BytesToGenerate = sizeof(secrets);
  if (BytesToGenerate % sizeof(blake3::Hash) != 0) {
    throw std::runtime_error(
        "The number of random bytes to generate should be divisible by "
        "`aes::BlockSize`!");
  }
  auto const hashes = BytesToGenerate / sizeof(blake3::Hash);
  dory::cuda::kernels::populate_sk<<<blocks(hashes), ThreadsPerBlock>>>(
      BytesToGenerate, *seed, &secrets);
  public_key.populate(*this);
}

void SecretKey::sign(uint8_t const* const msg, size_t const msg_len,
                     Signature& sig) const {
  std::array<Promise<>, Signature::Secrets + 1> promises;
  // 1. Blake3 the message on the CPU
  ExtendedHash const h(msg, msg_len);
  // 2. Fetch the data from the GPU VRAM (in parallel?).
  for (size_t i = 0; i < Signature::Secrets; i++) {
    auto const secret_index = h.secret_index(i);
    auto& proved_secret = sig.secrets[i];
    cudaMemcpyAsync(&proved_secret.secret, &secrets[secret_index],
                    sizeof(blake3::Hash), cudaMemcpyDeviceToHost,
                    promises[i].stream());
    public_key.merkle_tree.prove(secret_index, proved_secret.proof,
                                 promises[i].stream());
  }
  // // 3. Put the root and its sig.
  sig.eddsa = {};
  cudaMemcpyAsync(&sig.root, &public_key.merkle_tree.nodes[0],
                  sizeof(blake3::Hash), cudaMemcpyDeviceToHost,
                  promises[Signature::Secrets].stream());

  // RAII promises.
}

//////// PK

namespace dory::cuda::kernels {
__global__ void populate_pk(size_t const n, Secret const* const secrets,
                            blake3::Hash* const hashes) {
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= n) {
    return;
  }
  blake3::hash<sizeof(Secret)>(&secrets[i], hashes[i]);
}
}  // namespace dory::cuda::kernels

void PublicKey::populate(SecretKey const& sk) {
  dory::cuda::kernels::populate_pk<<<blocks(Hashes), ThreadsPerBlock>>>(
      Hashes, sk.secrets.data(), hashes.data());
  merkle_tree.populate(this);
}

namespace dory::cuda::kernels {
__global__ void check_precomputed_mp(ExtendedHash const& hash,
                                     Signature const& sig, MerkleTree const& mt,
                                     bool& valid) {
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= Signature::Secrets * MerkleTree::Proof::Length) {
    return;
  }
  auto const secret_index = hash.secret_index(i % SecretKey::LogSecrets);
  auto const& mp = decay(sig.secrets)[secret_index].proof;
  auto const mp_level = i / SecretKey::LogSecrets;
  auto const& node_tree = mt.proof_node(secret_index, mp_level, *mt.pk);
  auto const& node_proof = decay(mp.path)[mp_level];
  invalid_if_unequal(node_tree, node_proof, valid);
}

__global__ void check_secrets(ExtendedHash const& hash, Signature const& sig,
                              blake3::Hash const* hashes, bool& valid) {
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= Signature::Secrets) {
    return;
  }
  auto const secret_index = hash.secret_index(i);
  blake3::Hash secret_hash;
  blake3::hash<sizeof(Secret)>(
      reinterpret_cast<uint8_t const*>(&decay(sig.secrets)[i].secret),
      secret_hash);
  invalid_if_unequal(secret_hash, hashes[secret_index], valid);
}
}  // namespace dory::cuda::kernels

struct PkCheckIo {
  // In:
  ExtendedHash hash;
  Signature sig;
  // Out:
  bool valid;
};

DevicePool<PkCheckIo, MaxConcurrency> pk_check_io_pool;

bool PublicKey::check(uint8_t const* const msg, size_t msg_len,
                      Signature const& sig) {
  auto const unique_io = pk_check_io_pool.get();
  auto& io = *unique_io.get();

  // 1. Move the hash and sig to the GPU
  PkCheckIo prepared_io;
  prepared_io.hash = ExtendedHash(msg, msg_len);
  prepared_io.sig = sig;
  prepared_io.valid = true;
  cudaMemcpy(&io, &prepared_io, sizeof(PkCheckIo), cudaMemcpyHostToDevice);
  // 2. a. Start a kernel that checks each node of the merkle proofs in
  // parallel.
  dory::cuda::kernels::check_precomputed_mp<<<blocks(Signature::Secrets *
                                                     MerkleTree::Proof::Length),
                                              ThreadsPerBlock>>>(
      io.hash, io.sig, merkle_tree, io.valid);
  // 2. b. Start a kernel that checks each secret in parallel.
  dory::cuda::kernels::
      check_secrets<<<blocks(Signature::Secrets), ThreadsPerBlock>>>(
          io.hash, io.sig, decay(hashes), io.valid);
  // 2. c. The eddsa sig should have been checked before.
  bool ret;
  cudaMemcpy(&ret, &io.valid, sizeof(bool), cudaMemcpyDeviceToHost);
  return ret;
}

//////// MT

namespace dory::cuda::kernels {
__global__ void compute_mt_level(size_t const hashes,
                                 blake3::Hash const* const src,
                                 blake3::Hash* const dst) {
  size_t const i = blockIdx.x * blockDim.x + threadIdx.x;
  if (i >= hashes) {
    return;
  }
  blake3::hash<sizeof(blake3::Hash[2])>(&src[i * 2], dst[i]);
}
}  // namespace dory::cuda::kernels

void MerkleTree::populate(PublicKey const* const pk) {
  // Promise<> promise;
  cudaMemcpy(&this->pk, &pk, sizeof(PublicKey*), cudaMemcpyHostToDevice);
  // Let's compute the MT in parallel at each level.
  size_t nodes_this_level = (Nodes + 1) / 2;
  blake3::Hash const* src = pk->hashes.data();
  blake3::Hash* dst = &nodes[Nodes];
  while (true) {
    dst -= nodes_this_level;
    dory::cuda::kernels::compute_mt_level<<<
        blocks(nodes_this_level), ThreadsPerBlock /*, 0, promise.stream()*/>>>(
        nodes_this_level, src, dst);
    if (nodes_this_level == 0) {
      break;
    }  // Tree
    // if (nodes_this_level == Signature::Secrets) { break; } // Forest
    src = dst;
    nodes_this_level /= 2;
  };
}

void MerkleTree::prove(size_t const index, MerkleTree::Proof& proof,
                       cudaStream_t stream) const {
  PublicKey const* pk;
  cudaMemcpy(&pk, &this->pk, sizeof(PublicKey*), cudaMemcpyDeviceToHost);
  // 1. Fetch all the data from vram.
  for (size_t i = 0; i < MerkleTree::Proof::Length; i++) {
    // TODO: optimize by not calling proof_node
    cudaMemcpyAsync(&proof.path[i], &proof_node(index, i, *pk),
                    sizeof(blake3::Hash), cudaMemcpyDeviceToHost, stream);
  }
}

blake3::Hash const& MerkleTree::proof_node(size_t const leaf_index,
                                           size_t const level,
                                           PublicKey const& pk) const {
  if (level == MerkleTree::Proof::Length - 1) {
    // The last level should be fetched from the PK directly.
    return decay(pk.hashes)[leaf_index ^ 1];
  }
  size_t node_index = 0;
  size_t direction = 0;  // Left = 0; Right = 1;

  for (size_t depth = 0; depth < level; depth++) {
    direction = (leaf_index >> (MerkleTree::Proof::Length - depth)) & 1;
    auto const left_child = node_index * 2 + 1;
    node_index = left_child + direction;
  }
  // We return the sibbling of the last visited node.
  return decay(nodes)[direction ? (node_index - 1) : (node_index + 1)];
}

__device__ bool MerkleTree::Proof::check(size_t const leaf_index,
                                         blake3::Hash const& leaf,
                                         blake3::Hash const& root) const {
  // TODO
  return false;
}

//////// Signature

bool Signature::check(uint8_t const& msg, size_t const msg_len) {
  // 1. Blake3 the message on the CPU
  // 2. Start a kernel that checks each secrets + merkle proof
  throw "TODO";
}

//////// Extended hash

#include <chrono>
__host__ ExtendedHash::ExtendedHash(uint8_t const* const msg,
                                    size_t const msg_len) {
  // Let's fake it for now
  auto const start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start <
         std::chrono::nanoseconds(100))
    ;
  hash = {};
}

size_t ExtendedHash::secret_index(size_t const total_bit_offset) const {
  auto const byte_offset = total_bit_offset / 8;
  auto const bit_offset = total_bit_offset % 8;
  static size_t constexpr bit_mask = SecretKey::Secrets - 1;
  size_t const bit_shift = sizeof(size_t) - SecretKey::LogSecrets - bit_offset;
  auto const* const bytes = reinterpret_cast<uint8_t const*>(&hash);
  return (*reinterpret_cast<size_t const*>(&bytes[byte_offset]) >> bit_shift) &
         bit_mask;
}

}  // namespace dory::cuda

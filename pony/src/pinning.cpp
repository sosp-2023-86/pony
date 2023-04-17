#include <algorithm>
#include <cstdlib>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "pinning.hpp"

namespace dory::pony {

// return (name,value) trimmed pair from given "name=value" string.
// return empty string on missing parts
// "key=val" => ("key", "val")
// " key  =  val " => ("key", "val")
// "key=" => ("key", "")
// "val" => ("", "val")
static inline std::pair<std::string, std::string> extract_kv(
    char sep, std::string const &str) {
  auto n = str.find(sep);
  std::string k;

  std::string v;
  if (n == std::string::npos) {
    v = str;
  } else {
    k = str.substr(0, n);
    v = str.substr(n + 1);
  }
  std::unordered_set<std::string> threads = {
      {"bg", "pk-signer", "pk-verifier"}};
  if (threads.find(k) == threads.end()) {
    throw std::runtime_error("Unknown thread " + k + " in env. PONY_CORES");
  }
  return std::make_pair(k, v);
}

// return vector of key/value pairs from sequence of "K1=V1,K2=V2,.."
// "a=AAA,b=BBB,c=CCC,.." => {("a","AAA"),("b","BBB"),("c", "CCC"),...}
static inline std::unordered_map<std::string, std::string> extract_key_vals(
    std::string const &str) {
  std::string token;
  std::istringstream token_stream(str);
  std::unordered_map<std::string, std::string> rv{};
  while (std::getline(token_stream, token, ',')) {
    if (token.empty()) {
      continue;
    }
    auto kv = extract_kv('=', token);
    rv[kv.first] = kv.second;
  }
  return rv;
}

std::optional<int> get_core(std::string const &name) {
  std::unordered_set<std::string> threads = {
      {"bg", "pk-signer", "pk-verifier"}};
  if (threads.find(name) == threads.end()) {
    throw std::runtime_error("Unknown thread " + name + " upon get_core.");
  }

  auto *env_val_raw = std::getenv("PONY_CORES");
  std::string env_val{env_val_raw == nullptr ? "" : env_val_raw};
  auto const kvs = extract_key_vals(env_val);
  auto const kvs_iter = kvs.find(name);
  if (kvs_iter == kvs.end()) {
    return std::nullopt;
  }
  return std::stoi(kvs_iter->second);
}

}  // namespace dory::pony

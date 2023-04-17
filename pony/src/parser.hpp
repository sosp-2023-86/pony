#include <algorithm>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <fmt/core.h>
#include <toml.hpp>

#include "types.hpp"

namespace dory::pony {

class RuntimeConfig {
 public:
  RuntimeConfig(ProcId id, std::string const& default_config_path = "pony.toml")
      : my_id{id} {
    char const* env_config_path = getenv("PONY_CONFIG");
    char const* config_path =
        env_config_path ? env_config_path : default_config_path.c_str();

    toml::table tbl;
    try {
      tbl = toml::parse_file(config_path);
    } catch (const toml::parse_error& err) {
      // throw std::runtime_error(fmt::format("Failed to parse PONY_CONFIG
      // ({})", err));
      throw std::runtime_error("Failed to parse PONY_CONFIG");
    }

    std::optional<std::string> opt_nic = tbl["nic"].value<std::string>();
    if (!opt_nic) {
      throw std::runtime_error("You must provide the `nic` in the PONY_CONFIG");
    }
    nic = *opt_nic;

    std::optional<std::string> opt_mcast_group =
        tbl["mcast_group"].value<std::string>();
    if (!opt_mcast_group) {
      throw std::runtime_error(
          "You must provide the `mcast_group` in the PONY_CONFIG");
    }
    mcast_group = *opt_mcast_group;

    if (toml::array* arr = tbl["procs"].as_array()) {
      arr->for_each([this](auto&& el) {
        if constexpr (toml::is_number<decltype(el)>) {
          if (*el <= 0) {
            throw std::runtime_error(
                "Process ids have to be positive in `procs` of PONY_CONFIG");
          }
          this->ids.push_back(static_cast<ProcId>(*el));
        } else {
          throw std::runtime_error(
              "Process ids have to be integers in `procs` of PONY_CONFIG");
        }
      });

      std::set<ProcId> ids_dups(ids.begin(), ids.end());
      if (ids_dups.size() != ids.size()) {
        throw std::runtime_error(
            "There are duplicate entries in `procs` of PONY_CONFIG");
      }

      if (ids_dups.find(id) == ids_dups.end()) {
        throw std::runtime_error(fmt::format(
            "Your id (i.e., {}) is not in `procs` of PONY_CONFIG", id));
      }
    } else {
      throw std::runtime_error(
          "You must provide the `procs` in the PONY_CONFIG");
    }

    std::copy_if(ids.begin(), ids.end(), std::back_inserter(remote_ids),
                 [this](ProcId x) { return x != my_id; });
  }

  std::string deviceName() const { return nic; }

  ProcId myId() const { return my_id; }
  std::vector<ProcId> const& allIds() { return ids; }
  std::vector<ProcId> const& remoteIds() { return remote_ids; }

  std::string mcGroup() const { return mcast_group; }

 private:
  ProcId my_id;
  std::vector<ProcId> ids;
  std::vector<ProcId> remote_ids;
  std::string nic;
  std::string mcast_group;
};

}  // namespace dory::pony

#pragma once

#include <algorithm>
#include <chrono>
#include <cstdlib>

#include <iostream>

#include <dory/rpc/basic-client.hpp>
#include <dory/shared/types.hpp>

#include "../kvstores.hpp"
#include "app.hpp"

class Herd : public Application {
 public:
  enum Operation : uint64_t { PUT, GET };

  enum Response : uint64_t { OK, NOK };

  Herd(bool server, std::string const &config_string) {
    parse_config(config_string);

    req_op_offset = 0;
    req_key_offset = req_op_offset + round_up(sizeof(Operation), 8);
    req_value_offset =
        req_key_offset + round_up(static_cast<size_t>(key_size), 8);
    req_end_offset =
        req_value_offset + round_up(static_cast<size_t>(value_size), 8);

    res_res_offset = 0;
    res_value_offset = res_res_offset + round_up(sizeof(Response), 8);
    res_end_offset =
        res_value_offset + round_up(static_cast<size_t>(value_size), 8);

    if (server) {
      // Warm up the server
      prepare_requests();
      for (auto const &r : prepared_requests) {
        insert(r.data(), r.size());
      }
    } else {
      prepare_requests();
    }
  }

  size_t maxRequestSize() const {
    auto const max_put_size = req_end_offset;
    auto const max_get_size = req_value_offset;
    return std::max(max_put_size, max_get_size);
  }

  size_t maxResponseSize() const {
    auto const max_put_size = res_value_offset;
    auto const max_get_size = res_end_offset;
    return std::max(max_put_size, max_get_size);
  }

  std::vector<uint8_t> const &randomRequest() const {
    if (rand() % 100 < get_percentage) {
      return prepared_requests[rand() % prepared_requests_cnt];
    }

    return prepared_requests[prepared_requests_cnt +
                             rand() % prepared_requests_cnt];
  }

  void execute(uint8_t const *const request, size_t request_size,
               std::vector<uint8_t> &response) {
    // Deserialize request
    auto op = *reinterpret_cast<Operation const *>(request + req_op_offset);
    switch (op) {
      case PUT: {
        std::string key(
            reinterpret_cast<char const *>(request + req_key_offset), key_size);
        std::string value(
            reinterpret_cast<char const *>(request + req_value_offset),
            value_size);

        mica[key] = value;

        Response r = OK;
        std::memcpy(response.data() + res_res_offset, &r, sizeof(r));
      }; break;
      case GET: {
        std::string key(
            reinterpret_cast<char const *>(request + req_key_offset), key_size);
        auto value_it = mica.find(key);
        if (value_it != mica.end()) {
          Response r = OK;
          std::memcpy(response.data() + res_res_offset, &r, sizeof(r));
          std::memcpy(response.data() + res_value_offset,
                      value_it->second.data(), value_it->second.size());
        } else {
          Response r = NOK;
          std::memcpy(response.data() + res_res_offset, &r, sizeof(r));
        }
      }; break;
      default:
        throw std::logic_error("Unreachable!");
    }
  }

 private:
  void insert(uint8_t const *const request, size_t request_size) {
    // Deserialize request
    auto op = *reinterpret_cast<Operation const *>(request + req_op_offset);
    switch (op) {
      case PUT: {
        std::string key(
            reinterpret_cast<char const *>(request + req_key_offset), key_size);
        std::string value(
            reinterpret_cast<char const *>(request + req_value_offset),
            value_size);

        mica[key] = value;
      }; break;
      case GET: {
      }; break;
      default:
        throw std::logic_error("Unreachable!");
    }
  }

  void parse_config(std::string const &config_string) {
    std::stringstream ss(config_string);

    std::vector<size_t> vec;
    for (size_t i; ss >> i;) {
      vec.push_back(i);
      if (ss.peek() == ',') {
        ss.ignore();
      }
    }

    key_size = static_cast<int>(vec.at(0));
    value_size = static_cast<int>(vec.at(1));
    get_percentage = static_cast<int>(vec.at(2));
    get_success_percentage = static_cast<int>(vec.at(3));
    prepared_requests_cnt = vec.size() > 4 ? vec.at(4) : 1024;
  }

  void prepare_requests() {
    srand(1023);
    std::vector<std::vector<uint8_t>> keys;

    size_t unique_keys =
        prepared_requests_cnt +
        prepared_requests_cnt * (100 - get_success_percentage) / 100;
    keys.resize(unique_keys);

    for (size_t i = 0; i < unique_keys; i++) {
      keys[i].resize(key_size);
      kvstores::mkrndstr_ipa(key_size, keys[i].data(), true);
    }

    size_t circular_index = 0;

    for (size_t i = 0; i < prepared_requests_cnt; i++) {
      std::vector<uint8_t> req;
      req.resize(req_value_offset);

      Operation o = GET;
      std::memcpy(req.data() + req_op_offset, &o, sizeof(o));
      std::memcpy(req.data() + req_key_offset,
                  keys[circular_index % unique_keys].data(), key_size);

      prepared_requests.push_back(req);
      circular_index++;
    }

    for (size_t i = 0; i < prepared_requests_cnt; i++) {
      std::vector<uint8_t> req;
      req.resize(req_end_offset);

      Operation o = PUT;
      std::memcpy(req.data() + req_op_offset, &o, sizeof(o));
      std::memcpy(req.data() + req_key_offset,
                  keys[circular_index % unique_keys].data(), key_size);
      kvstores::mkrndstr_ipa(value_size, req.data() + req_value_offset, true);

      prepared_requests.push_back(req);
      circular_index++;
    }
  }

  size_t round_up(size_t numToRound, size_t multiple) {
    return ((numToRound + multiple - 1) / multiple) * multiple;
  }

  int key_size;
  int value_size;
  int get_percentage;
  int get_success_percentage;
  size_t prepared_requests_cnt;
  size_t get_end_index;

  size_t req_op_offset;
  size_t req_key_offset;
  size_t req_value_offset;
  size_t req_end_offset;

  size_t res_res_offset;
  size_t res_value_offset;
  size_t res_end_offset;

  std::vector<std::vector<uint8_t>> prepared_requests;

  std::unordered_map<std::string, std::string> mica;
};

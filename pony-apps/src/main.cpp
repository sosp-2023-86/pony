#include <chrono>
#include <thread>

#include <fmt/core.h>
#include <lyra/lyra.hpp>

#include <dory/pony/pony.hpp>
#include <dory/shared/unused-suppressor.hpp>

int main(int argc, char* argv[]) {
  // dory::ignore(argc);
  // dory::ignore(argv);

  lyra::cli cli;
  bool get_help = false;
  int local_id;

  cli.add_argument(lyra::help(get_help))
      .add_argument(lyra::opt(local_id, "id")
                        .required()
                        .name("-l")
                        .name("--local-id")
                        .help("ID of the present process"));

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

  unsigned char sm = 'a';
  unsigned long long smlen_p = 0;
  const unsigned char m = 'b';
  unsigned long long mlen = 1;
  const unsigned char sk = 'c';

  fmt::print("Hi pony!\n");
  pony_sign(&sm, smlen_p, &m, mlen, &sk);
  dory::pony::sign(&sm, smlen_p, &m, mlen, &sk);

  fmt::print("Pony class\n");
  dory::pony::Pony pony(local_id);
  dory::pony::Signature signature;
  while (true) {
    pony.sign(signature, &m, mlen);
    fmt::print("Signed.\n");
    {
      auto const valid = pony.verify(signature, &m, mlen, local_id);
      fmt::print("Signature is valid: {}.\n", valid);
    }
    {
      auto const valid = pony.slow_verify(signature, &m, mlen, local_id);
      fmt::print("[slow] Signature is valid: {}.\n", valid);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  std::this_thread::sleep_for(std::chrono::seconds(10));

  // if (local_id == 1 || local_id == 2) {
  //   std::this_thread::sleep_for(std::chrono::seconds(4));
  //   pony.send(static_cast<uint8_t>(local_id));
  // }

  // while (true) {
  //   pony.receive();
  // }

  return 0;
}

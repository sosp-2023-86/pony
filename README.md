# Pony

## Requirements

- [conan](https://conan.io/) package manager
    ```sh
    pip3 install --user "conan>=1.47.0"
    ```

    make sure to set the default ABI to C++11 with:

    ```sh
    conan profile new default --detect  # Generates default profile detecting GCC and sets old ABI
    conan profile update settings.compiler.libcxx=libstdc++11 default  # Sets libcxx to C++11 ABI
    ```

- cmake v3.9.x
- clang-format >= v6.0.0

## Build

Run from within the root:

```sh
./build.py
```

this will create all conan packages and build the executables.

The source code for Pony is under `pony` and `pony-apps`.

__Note:__ If `gcc` is available, it is used as the default compiler. In a system with `clang` only, then `clang` becomes the default compiler. In any case, you can check the available compilers/compiler versions by calling `./build.py --help`.


## Docker

You can manually build the Dockerfile under the root of this repo.

```sh
docker build -t dory .
```
---


## Usage

Refer to the respective package READMEs.

#!/usr/bin/env python3

from conans import ConanFile, CMake


class DoryPonyConan(ConanFile):
    name = "dory-pony"
    version = "0.0.1"
    license = "MIT"
    # url = "TODO"
    description = "RDMA pony"
    settings = {
        "os": None,
        "compiler": {
            "gcc": {"libcxx": "libstdc++11", "cppstd": ["17", "20"], "version": None},
            "clang": {"libcxx": "libstdc++11", "cppstd": ["17", "20"], "version": None},
        },
        "build_type": None,
        "arch": None,
    }
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
        "log_level": ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL", "OFF"],
        "lto": [True, False],
        "slim_build": [True, False],
    }
    default_options = {
        "shared": False,
        "fPIC": True,
        "log_level": "INFO",
        "lto": True,
        "slim_build": True,
        "dory-crypto:isa": "avx2",
    }
    generators = "cmake"
    exports_sources = "src/*"
    python_requires = "dory-compiler-options/0.0.1@dory/stable"

    def configure(self):
        pass

    def requirements(self):
        self.requires("dory-conn/0.0.1")
        self.requires("dory-crypto/0.0.1")
        self.requires("dory-ctrl/0.0.1")
        self.requires("dory-memory/0.0.1")
        self.requires("dory-memstore/0.0.1")
        self.requires("dory-shared/0.0.1")

        self.requires("hipony-enumerate/2.4.1")
        self.requires("tomlplusplus/3.2.0")
        self.requires("fmt/7.1.3")
        self.requires("xxhash/0.8.0")

        # Required for test only
        self.requires("lyra/1.5.1")

    def build(self):
        self.python_requires["dory-compiler-options"].module.setup_cmake(
            self.build_folder
        )
        generator = self.python_requires["dory-compiler-options"].module.generator()
        cmake = CMake(self, generator=generator)

        self.python_requires["dory-compiler-options"].module.set_options(cmake)
        lto_decision = self.python_requires[
            "dory-compiler-options"
        ].module.lto_decision(cmake, self.options.lto)
        cmake.definitions["DORY_LTO"] = str(lto_decision).upper()
        cmake.definitions["SHARED_LIB"] = self.options.shared
        cmake.definitions["SLIM_BUILD"] = self.options.slim_build
        cmake.definitions["DALEK_AVX"] = (
            self.default_options["dory-crypto:isa"] == "avx2"
        )
        cmake.definitions["SPDLOG_ACTIVE_LEVEL"] = "SPDLOG_LEVEL_{}".format(
            self.options.log_level
        )

        cmake.configure(source_folder="src")
        cmake.build()

    def package(self):
        self.copy("*.hpp", dst="include/dory/pony", src="src")
        self.copy("*.inc", dst="include/dory/pony", src="src")
        self.copy(
            "*.hpp", dst="include/dory/pony/export/internal", src="export/internal"
        )
        self.copy("*.a", dst="lib", src="lib", keep_path=False)
        self.copy("*.so", dst="lib", src="lib", keep_path=False)
        self.copy("*", dst="bin", src="bin")

    def deploy(self):
        if self.options.shared:
            self.copy(
                "*.hpp",
                dst="include/dory/pony",
                src="include/dory/pony/export",
                keep_path=True,
            )
            self.copy(
                "*.so",
                dst="lib/" + str(self.settings.build_type).lower(),
                src="lib",
                keep_path=False,
            )
        self.copy("*", dst="bin", src="bin")

    def package_info(self):
        self.cpp_info.libs = ["dorypony"]

        if self.options.shared:
            # No need to export these when creating an .so
            # self.cpp_info.system_libs = ["cudadevrt", "cudart", "rt", "pthread", "dl"]
            pass
        else:
            self.cpp_info.system_libs = [
                "cuda",
                "cudadevrt",
                "cudart_static",
                "rt",
                "pthread",
                "dl",
            ]

        self.cpp_info.cxxflags = self.python_requires[
            "dory-compiler-options"
        ].module.get_cxx_options_for(self.settings.compiler, self.settings.build_type)


if __name__ == "__main__":
    import os, pathlib, sys

    # Find dory root directory
    root_dir = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
    while not os.path.isfile(os.path.join(root_dir, ".dory-root")):
        root_dir = root_dir.parent

    sys.path.append(os.path.join(root_dir, "conan", "invoker"))

    import invoker

    invoker.run()

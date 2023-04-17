cmake_minimum_required(VERSION 3.18)
project(dorypony CXX CUDA)

include(${CMAKE_BINARY_DIR}/setup.cmake)
dory_setup_cmake()

# To bump to a version 17, you need CMake 3.18 or above. You can install it as
# follows: wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc
# 2>/dev/null | sudo apt-key add - sudo apt-add-repository 'deb
# https://apt.kitware.com/ubuntu/ bionic main' sudo apt update && sudo apt
# install cmake

set(CMAKE_CUDA_STANDARD 17)
set(CMAKE_CUDA_STANDARD_REQUIRED ON)
set(CMAKE_CUDA_SEPARABLE_COMPILATION ON)

# message(STATUS "Selecting appropriate gencodes for x86 CPU architectures")
# set(GPU_ARCHS "60") # Default minimum supported CUDA gencode for cuML
#
# if(CUDA_VERSION_MAJOR GREATER_EQUAL 9) set(GPU_ARCHS "${GPU_ARCHS};70")
# endif()
#
# if(CUDA_VERSION_MAJOR GREATER_EQUAL 10) set(GPU_ARCHS "${GPU_ARCHS};75")
# endif()
#
# if(CUDA_VERSION_MAJOR GREATER_EQUAL 11) set(GPU_ARCHS "${GPU_ARCHS};80;86")
# endif()
#
# set(CMAKE_CUDA_ARCHITECTURES "${GPU_ARCHS}") set(CUDA_ARCHITECTURES
# "${CMAKE_CUDA_ARCHITECTURES}")
#
# message(STATUS "Building for GPU_ARCHS = ${GPU_ARCHS}") foreach(arch
# ${GPU_ARCHS}) set(CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} -gencode
# arch=compute_${arch},code=sm_${arch}") endforeach()

if(NOT DEFINED ${CMAKE_CUDA_ARCHITECTURES})
  set(CMAKE_CUDA_ARCHITECTURES 52 61 75 86)
endif()
message(STATUS "CUDA architectures set to ${CMAKE_CUDA_ARCHITECTURES}")

string(
  CONCAT CMAKE_CUDA_INTFLAGS_STR
         "-Xcompiler "
         "-Wall,-Werror,-Wconversion,-Wfloat-equal,"
         "-Wpointer-arith,-Wswitch-default,"
         "-Wpacked,-Wextra,-Winvalid-pch,"
         "-Wmissing-field-initializers,"
         "-Wunreachable-code,-Wcast-align,-Wcast-qual,"
         "-Wdisabled-optimization,-Wformat=2,"
         "-Wformat-nonliteral,-Wuninitialized,"
         "-Wformat-security,-Wformat-y2k,-Winit-self,"
         # Commented out, otherwise the separable compilation fails
         # "-Wmissing-declarations,"
         "-Wmissing-include-dirs,"
         "-Wstrict-overflow=5,"
         "-Wno-unused,-Wctor-dtor-privacy,-Wsign-promo,"
         "-Woverloaded-virtual,-Wextra-semi")

string(
  CONCAT CMAKE_CUDA_EXTFLAGS_STR
         ""
         "-Werror all-warnings "
         "-Wreorder "
         # "-Wdefault-stream-launch " "-Wmissing-launch-bounds "
         "-Wext-lambda-captures-this "
         "-Wno-deprecated-declarations -Wno-deprecated-gpu-targets")

set(CMAKE_CUDA_FLAGS
    "${CMAKE_CUDA_FLAGS} ${CMAKE_CUDA_EXTFLAGS_STR} ${CMAKE_CUDA_INTFLAGS_STR}")

message(STATUS "CMAKE_CUDA_FLAGS: " ${CMAKE_CUDA_FLAGS})

string(TIMESTAMP BUILD_TIME "%Y-%m-%d %H:%M")
add_definitions(-DBINARY_BUILD_TIME="${BUILD_TIME}")

set(PONY_TESTS "ping" "tput" "scalability")

set(COMMON_SOURCE
    pony.cpp
    pinning.cpp
    sanity/compile-time.cpp
    sanity/run-time.cpp
    cuda-signer.cu
    cuda-verifier.cu
    cuda/check.cu
    # cuda/blake3.cu
    cuda/core.cu
    cuda/alloc.cu)

add_executable(gpu-load test/gpu-load.cu)
target_link_libraries(
  gpu-load
  cuda
  cudadevrt
  cudart_static
  rt
  pthread
  dl
  ${CONAN_LIBS})

if(SLIM_BUILD)
  # cmake-format: off
  set(SCHEME                           0) # 0 -> HORS, 1 -> WOTS

  set(HORS_LOG_SECRETS_PER_SECRET_KEY  8)
  set(HORS_SECRETS_PER_SIGNATURE      64)
  set(HORS_SIGNATURES_PER_SECRET_KEY   1)
  set(HORS_PK_EMBEDDING                0) # 0 -> Full, 1 -> Merkle, 2 -> None
  set(HORS_LOG_NB_ROOTS                0)

  set(WOTS_LOG_SECRETS_DEPTH           1)
  set(WOTS_VERIFY_ON_GPU               0)

  set(PRESEND_EDDSA_ONLY               0)
  # cmake-format: on

  foreach(test ${PONY_TESTS})
    if(DALEK_AVX)
      set(SLIM_BINARY pony-${test}-slim-avx)
    else()
      set(SLIM_BINARY pony-${test}-slim)
    endif()

    add_executable(${SLIM_BINARY} ${HEADER_TIDER} test/${test}.cpp
                                  ${COMMON_SOURCE})

    target_compile_definitions(
      ${SLIM_BINARY}
      PUBLIC SCHEME=${SCHEME}
             HORS_LOG_SECRETS_PER_SECRET_KEY=${HORS_LOG_SECRETS_PER_SECRET_KEY}
             HORS_SECRETS_PER_SIGNATURE=${HORS_SECRETS_PER_SIGNATURE}
             HORS_SIGNATURES_PER_SECRET_KEY=${HORS_SIGNATURES_PER_SECRET_KEY}
             HORS_PK_EMBEDDING=${HORS_PK_EMBEDDING}
             HORS_LOG_NB_ROOTS=${HORS_LOG_NB_ROOTS}
             WOTS_LOG_SECRETS_DEPTH=${WOTS_LOG_SECRETS_DEPTH}
             WOTS_VERIFY_ON_GPU=${WOTS_VERIFY_ON_GPU}
             PRESEND_EDDSA_ONLY=${PRESEND_EDDSA_ONLY})

    target_link_libraries(
      ${SLIM_BINARY}
      cuda
      cudadevrt
      cudart_static
      rt
      pthread
      dl
      ${CONAN_LIBS})
  endforeach()

  add_library(dorypony ${HEADER_TIDER} ${COMMON_SOURCE} export/pony.cpp)

  target_compile_definitions(
    dorypony
    PUBLIC SCHEME=${SCHEME}
           HORS_LOG_SECRETS_PER_SECRET_KEY=${HORS_LOG_SECRETS_PER_SECRET_KEY}
           HORS_SECRETS_PER_SIGNATURE=${HORS_SECRETS_PER_SIGNATURE}
           HORS_SIGNATURES_PER_SECRET_KEY=${HORS_SIGNATURES_PER_SECRET_KEY}
           HORS_PK_EMBEDDING=${HORS_PK_EMBEDDING}
           HORS_LOG_NB_ROOTS=${HORS_LOG_NB_ROOTS}
           WOTS_LOG_SECRETS_DEPTH=${WOTS_LOG_SECRETS_DEPTH}
           WOTS_VERIFY_ON_GPU=${WOTS_VERIFY_ON_GPU}
           PRESEND_EDDSA_ONLY=${PRESEND_EDDSA_ONLY})

  configure_file(export/internal/compile-time-config.hpp.in
                 export/internal/compile-time-config.hpp)

  if(SHARED_LIB)
    # --exclude-libs tells the linker that the symbols of the .a linked together
    # should not be automatically exported
    target_link_libraries(dorypony ${CONAN_LIBS} "-Wl,--no-whole-archive"
                          "-Wl,--exclude-libs,ALL")
    set_target_properties(dorypony PROPERTIES CUDA_VISIBILITY_PRESET hidden)
  endif()

  # Needed when generating a static library with separable compilation
  set_property(TARGET dorypony PROPERTY CUDA_RESOLVE_DEVICE_SYMBOLS ON)
else()
  # HORS-based pings
  # cmake-format: off
  set(HORS_LOG_SECRETS_PER_SECRET_KEY  19  20  21  23  15  16  17  19  13  14  15  17  12  13  14  16  11  12  13  15  10  11  12  14   9  10  11  13   8   9  10  12   9   9   8   8  9  8 )
  set(HORS_SECRETS_PER_SIGNATURE        8   8   8   8  12  12  12  12  14  14  14  14  16  16  16  16  19  19  19  19  24  24  24  24  32  32  32  32  64  64  64  64  32  32  64  64 32 64 )
  set(HORS_SIGNATURES_PER_SECRET_KEY    1   2   4  16   1   3   6  26   1   2   4  16   1   2   4  16   1   2   4  16   1   2   4  16   1   2   4  16   1   2   4  16   1   1   1   1  1  1 )
  set(HORS_PK_EMBEDDING                 1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   1   0   0   0   0  2  2 )
  set(HORS_LOG_NB_ROOTS                 3   3   3   3   4   4   4   4   4   4   4   4   4   4   4   4   5   5   5   5   5   5   5   5   5   5   5   5   6   6   6   6   0   0   0   0  0  0 )
  set(PRESEND_EDDSA_ONLY                0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   0   1   0   1  0  0 )
  # cmake-format: on

  foreach(
    logt
    sps
    spsk
    embedded_pk
    rts
    eddsa
    IN
    ZIP_LISTS
    HORS_LOG_SECRETS_PER_SECRET_KEY
    HORS_SECRETS_PER_SIGNATURE
    HORS_SIGNATURES_PER_SECRET_KEY
    HORS_PK_EMBEDDING
    HORS_LOG_NB_ROOTS
    PRESEND_EDDSA_ONLY)

    foreach(test ${PONY_TESTS})
      add_executable(
        pony-${test}-hors-${logt}-${sps}-${spsk}-${embedded_pk}-${rts}-${eddsa}
        ${HEADER_TIDER} test/${test}.cpp ${COMMON_SOURCE})

      target_compile_definitions(
        pony-${test}-hors-${logt}-${sps}-${spsk}-${embedded_pk}-${rts}-${eddsa}
        PUBLIC SCHEME=0
               HORS_LOG_SECRETS_PER_SECRET_KEY=${logt}
               HORS_SECRETS_PER_SIGNATURE=${sps}
               HORS_SIGNATURES_PER_SECRET_KEY=${spsk}
               HORS_PK_EMBEDDING=${embedded_pk}
               HORS_LOG_NB_ROOTS=${rts}
               WOTS_LOG_SECRETS_DEPTH=1
               WOTS_VERIFY_ON_GPU=0
               PRESEND_EDDSA_ONLY=${eddsa})

      target_link_libraries(
        pony-${test}-hors-${logt}-${sps}-${spsk}-${embedded_pk}-${rts}-${eddsa}
        cuda
        cudadevrt
        cudart_static
        rt
        pthread
        dl
        ${CONAN_LIBS})
    endforeach()
  endforeach()

  # WOTS-based pings
  # cmake-format: off
  set(WOTS_LOG_SECRETS_DEPTH 1 2 4 8 1 2 4 8 1 2 4 8)
  set(WOTS_VERIFY_ON_GPU     0 0 0 0 1 1 1 1 0 0 0 0)
  set(PRESEND_EDDSA_ONLY     0 0 0 0 0 0 0 0 1 1 1 1)
  # cmake-format: on

  foreach(
    logw
    gpu
    eddsa
    IN
    ZIP_LISTS
    WOTS_LOG_SECRETS_DEPTH
    WOTS_VERIFY_ON_GPU
    PRESEND_EDDSA_ONLY)

    foreach(test ${PONY_TESTS})
      add_executable(pony-${test}-wots-${logw}-${gpu}-${eddsa}
                     ${HEADER_TIDER} test/${test}.cpp ${COMMON_SOURCE})

      target_compile_definitions(
        pony-${test}-wots-${logw}-${gpu}-${eddsa}
        PUBLIC SCHEME=1
               HORS_LOG_SECRETS_PER_SECRET_KEY=8
               HORS_SECRETS_PER_SIGNATURE=64
               HORS_SIGNATURES_PER_SECRET_KEY=1
               HORS_PK_EMBEDDING=0
               HORS_LOG_NB_ROOTS=0
               WOTS_LOG_SECRETS_DEPTH=${logw}
               WOTS_VERIFY_ON_GPU=${gpu}
               PRESEND_EDDSA_ONLY=${eddsa})

      target_link_libraries(
        pony-${test}-wots-${logw}-${gpu}-${eddsa}
        cuda
        cudadevrt
        cudart_static
        rt
        pthread
        dl
        ${CONAN_LIBS})
    endforeach()
  endforeach()

  foreach(HORS_LOG_SECRETS_PER_SECRET_KEY RANGE 8 19)
    add_executable(gpu-tput-${HORS_LOG_SECRETS_PER_SECRET_KEY} test/gpu-tput.cu
                                                               ${COMMON_SOURCE})
    target_link_libraries(
      gpu-tput-${HORS_LOG_SECRETS_PER_SECRET_KEY}
      cuda
      cudadevrt
      cudart_static
      rt
      pthread
      dl
      ${CONAN_LIBS})

    target_compile_definitions(
      gpu-tput-${HORS_LOG_SECRETS_PER_SECRET_KEY}
      PUBLIC SCHEME=0
             HORS_LOG_SECRETS_PER_SECRET_KEY=${HORS_LOG_SECRETS_PER_SECRET_KEY}
             HORS_SECRETS_PER_SIGNATURE=19
             HORS_SIGNATURES_PER_SECRET_KEY=1
             HORS_PK_EMBEDDING=1
             HORS_LOG_NB_ROOTS=5
             WOTS_LOG_SECRETS_DEPTH=1
             WOTS_VERIFY_ON_GPU=0
             PRESEND_EDDSA_ONLY=0)
  endforeach()
endif()

# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 avwarez

# Cross-compile natd for Windows ARM64 with llvm-mingw.
#   cmake -S . -B build-win -G Ninja -DCMAKE_TOOLCHAIN_FILE=cmake/aarch64-w64-mingw32.cmake \
#         -DLLVM_MINGW=$HOME/toolchains/llvm-mingw-<version>-ucrt-ubuntu-22.04-aarch64
# Binaries are linked statically (no libc++.dll / libunwind.dll to ship) and
# run under Wine ARM64 or on Windows on ARM.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR ARM64)
if(NOT LLVM_MINGW)
    set(LLVM_MINGW "$ENV{LLVM_MINGW}")
endif()
set(CMAKE_C_COMPILER   "${LLVM_MINGW}/bin/aarch64-w64-mingw32-clang")
set(CMAKE_CXX_COMPILER "${LLVM_MINGW}/bin/aarch64-w64-mingw32-clang++")
set(CMAKE_RC_COMPILER  "${LLVM_MINGW}/bin/aarch64-w64-mingw32-windres")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")
set(CMAKE_FIND_ROOT_PATH "${LLVM_MINGW}/aarch64-w64-mingw32")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

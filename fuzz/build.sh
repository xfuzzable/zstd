#!/bin/bash

set -ex

rm -rf build

mkdir -p build

export CC="clang"
export CXX="clang++"
export LD="clang"
export CFLAGS="-fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div -fno-omit-frame-pointer -fno-optimize-sibling-calls -fsanitize=address -fsanitize-address-use-after-scope -fPIC"
export LDFLAGS="$CFLAGS $PWD/build/afl-persist-loop.o"

# ===== Uncomment following lines to enable persist mode =====
export CFLAGS="$CFLAGS -DFUZZ_PERSISTENT"
export LDFLAGS="$LDFLAGS -Wl,--wrap,exit,--wrap,main"
# ============================================================

$CC $CFLAGS -c -o build/afl-persist-loop.o afl-persist-loop.c
ar -rcs build/libafl-persist-loop.a build/afl-persist-loop.o

cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../../build/cmake

make -j VERBOSE=1

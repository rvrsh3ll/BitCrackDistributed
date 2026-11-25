#!/usr/bin/env bash
set -euo pipefail

# Simple Linux build + package helper.
# Usage: ./scripts/package_linux.sh [build_dir]
# Env vars:
#   CONFIG=Release|Debug (default: Release)
#   DISABLE_CUDA=ON|OFF (default: OFF)
#   RUN_TESTS=1 to build+run bitcrack_tests
#   CMAKE_ARGS="..." to pass extra args to CMake configure

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="${1:-build_linux}"
CONFIG="${CONFIG:-Release}"
DISABLE_CUDA="${DISABLE_CUDA:-OFF}"
RUN_TESTS_FLAG="${RUN_TESTS:-0}"
EXTRA_CMAKE_ARGS=${CMAKE_ARGS:-}

mkdir -p "$ROOT_DIR/$BUILD_DIR"

cmake -S "$ROOT_DIR" -B "$ROOT_DIR/$BUILD_DIR" \
  -DCMAKE_BUILD_TYPE="$CONFIG" \
  -DDISABLE_CUDA="$DISABLE_CUDA" \
  $EXTRA_CMAKE_ARGS

cmake --build "$ROOT_DIR/$BUILD_DIR" --config "$CONFIG" --target bitcrack-distributed

if [ "$RUN_TESTS_FLAG" = "1" ]; then
  cmake --build "$ROOT_DIR/$BUILD_DIR" --config "$CONFIG" --target bitcrack_tests
  if [ -x "$ROOT_DIR/$BUILD_DIR/tests/bitcrack_tests" ]; then
    "$ROOT_DIR/$BUILD_DIR/tests/bitcrack_tests"
  elif [ -x "$ROOT_DIR/$BUILD_DIR/$CONFIG/tests/bitcrack_tests" ]; then
    "$ROOT_DIR/$BUILD_DIR/$CONFIG/tests/bitcrack_tests"
  fi
fi

DIST_DIR="$ROOT_DIR/dist/linux"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/bin" "$DIST_DIR/gpu/kernels"

# Locate built binary for single- or multi-config generators
BIN_SRC=""
for candidate in \
  "$ROOT_DIR/$BUILD_DIR/bitcrack-distributed" \
  "$ROOT_DIR/$BUILD_DIR/$CONFIG/bitcrack-distributed" \
  "$ROOT_DIR/$BUILD_DIR/$CONFIG/bitcrack-distributed-cli"; do
  if [ -x "$candidate" ]; then
    BIN_SRC="$candidate"
    break
  fi
done

if [ -z "$BIN_SRC" ]; then
  echo "Failed to locate built binary in $BUILD_DIR (config=$CONFIG)" >&2
  exit 1
fi

cp "$BIN_SRC" "$DIST_DIR/bin/"

# Copy kernels (best effort)
if [ -d "$ROOT_DIR/gpu/kernels" ]; then
  cp -a "$ROOT_DIR/gpu/kernels/." "$DIST_DIR/gpu/kernels/" 2>/dev/null || true
fi

# Copy a sample config if present
if [ -f "$ROOT_DIR/config.json" ]; then
  cp "$ROOT_DIR/config.json" "$DIST_DIR/config.sample.json"
fi

# Tarball
mkdir -p "$ROOT_DIR/dist"
tar -C "$DIST_DIR/.." -czf "$ROOT_DIR/dist/bitcrack-distributed-linux.tar.gz" linux

echo "Packaged to dist/bitcrack-distributed-linux.tar.gz"

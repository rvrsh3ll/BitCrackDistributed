#!/usr/bin/env bash
# Build the CPU-only bitcrack-distributed CLI for macOS (Apple Silicon or
# Intel) against a static OpenSSL built from a pinned, checksummed source
# tarball, so the binary needs nothing but the macOS system libraries.
#
# Usage: scripts/build_macos.sh [build_dir]        (default: build-macos-<arch>)
#
# Run it on a Mac. Needs Xcode command line tools (clang), cmake, ninja
# (brew install cmake ninja), perl, make, curl and tar.
#
# Environment:
#   ARCH        arm64 or x86_64 (default: this machine's architecture). The
#               other one is cross-compiled but cannot be run here without
#               Rosetta, so tests only run for the native architecture.
#   MACOS_MIN   minimum macOS version (default 11.0 for arm64, 10.15 for x86_64).
#   WITH_TESTS  1: also build bitcrack_tests (default 0).
#   PACKAGE     1: also write <build_dir>/dist/bitcrack-distributed-<TAG>-macos-
#               <arch>-cpu.tar.gz (binary, README.md, LICENSE, MACOS.md,
#               RUN.txt) and its .sha256.
#   PKG_TAG     version label used in the package name (default v<version> from
#               CMakeLists.txt).
#   JOBS        parallel jobs (default: hw.ncpu).
#
# GPU (CUDA/OpenCL) is not built: Macs have no CUDA, so this is the CPU searcher.
# The binary is ad-hoc signed (required to run on Apple Silicon), not notarized.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
[ "$(uname -s)" = Darwin ] || { echo "build_macos.sh: run this on macOS" >&2; exit 1; }

ARCH="${ARCH:-$(uname -m)}"
case "$ARCH" in
  arm64)  OSSL_TARGET=darwin64-arm64-cc;  DEFAULT_MIN=11.0 ;;
  x86_64) OSSL_TARGET=darwin64-x86_64-cc; DEFAULT_MIN=10.15 ;;
  *) echo "build_macos.sh: unsupported ARCH=$ARCH (arm64 or x86_64)" >&2; exit 1 ;;
esac
MACOS_MIN="${MACOS_MIN:-$DEFAULT_MIN}"
BUILD_DIR="${1:-$ROOT_DIR/build-macos-$ARCH}"
case "$BUILD_DIR" in /*) ;; *) BUILD_DIR="$PWD/$BUILD_DIR" ;; esac
WITH_TESTS="${WITH_TESTS:-0}"
PACKAGE="${PACKAGE:-0}"
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"

OPENSSL_VERSION=3.4.1
OPENSSL_SHA256=002a2d6b30b58bf4bea46c43bdd96365aaf8daa6c428782aa4feee06da197df3
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"

die() { echo "build_macos.sh: $*" >&2; exit 1; }
sha256_of() { shasum -a 256 "$1" | awk '{print $1}'; }

DEPS="$BUILD_DIR/deps"
# OpenSSL compiles its install paths into the library. Use /etc/ssl for the
# trust store (macOS ships /etc/ssl/cert.pem, so Electrum TLS verifies out of
# the box) and a neutral install prefix, staged with DESTDIR, so the binary
# carries no build-host paths.
OSSL_RUNTIME_PREFIX=/opt/openssl-macos
OSSL_STAGE="$DEPS/openssl-$OPENSSL_VERSION-$ARCH-min$MACOS_MIN"
OSSL_PREFIX="$OSSL_STAGE$OSSL_RUNTIME_PREFIX"
mkdir -p "$DEPS"

# --- OpenSSL (static) --------------------------------------------------------
if [ ! -f "$OSSL_PREFIX/lib/libssl.a" ]; then
  tarball="$DEPS/openssl-$OPENSSL_VERSION.tar.gz"
  if [ ! -f "$tarball" ]; then
    echo "Downloading OpenSSL $OPENSSL_VERSION"
    curl -fsSL --retry 3 -o "$tarball.part" "$OPENSSL_URL"
    mv "$tarball.part" "$tarball"
  fi
  [ "$(sha256_of "$tarball")" = "$OPENSSL_SHA256" ] || die "OpenSSL tarball checksum mismatch"
  src="$DEPS/openssl-src-$ARCH"
  rm -rf "$src" && mkdir -p "$src"
  tar -xzf "$tarball" -C "$src" --strip-components=1
  echo "Building OpenSSL $OPENSSL_VERSION for $OSSL_TARGET (macOS >= $MACOS_MIN)"
  (
    cd "$src"
    ./Configure "$OSSL_TARGET" "-mmacosx-version-min=$MACOS_MIN" \
      no-shared no-tests no-docs no-apps no-module no-engine \
      --prefix="$OSSL_RUNTIME_PREFIX" --openssldir=/etc/ssl --libdir=lib \
      >"$DEPS/openssl-configure.log" 2>&1
    make -j"$JOBS" build_libs >"$DEPS/openssl-make.log" 2>&1
    make install_dev DESTDIR="$OSSL_STAGE" >"$DEPS/openssl-install.log" 2>&1
  ) || { tail -30 "$DEPS"/openssl-*.log >&2; die "OpenSSL build failed; see $DEPS/openssl-*.log"; }
fi
[ -f "$OSSL_PREFIX/lib/libssl.a" ] && [ -f "$OSSL_PREFIX/lib/libcrypto.a" ] || die "static OpenSSL missing under $OSSL_PREFIX"

# --- bitcrack-distributed ----------------------------------------------------
TARGETS=(bitcrack-distributed)
[ "$WITH_TESTS" = 1 ] && TARGETS+=(bitcrack_tests)
cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET="$MACOS_MIN" \
  "-DCMAKE_CXX_FLAGS=-ffile-prefix-map=$ROOT_DIR/=" \
  -DOPENSSL_ROOT_DIR="$OSSL_PREFIX" \
  -DOPENSSL_INCLUDE_DIR="$OSSL_PREFIX/include" \
  -DOPENSSL_SSL_LIBRARY="$OSSL_PREFIX/lib/libssl.a" \
  -DOPENSSL_CRYPTO_LIBRARY="$OSSL_PREFIX/lib/libcrypto.a" \
  -DOPENSSL_USE_STATIC_LIBS=TRUE \
  -DBITCRACK_DISABLE_GPU=ON \
  -DDISABLE_CUDA=ON \
  -DBITCRACK_COPY_BUILD_TO_DIST=OFF \
  -DBITCRACK_BUILD_TESTS="$([ "$WITH_TESTS" = 1 ] && echo ON || echo OFF)"
for t in "${TARGETS[@]}"; do
  cmake --build "$BUILD_DIR" --target "$t" -j "$JOBS"
done

BIN=""
for c in "$BUILD_DIR/Release/bitcrack-distributed" "$BUILD_DIR/bitcrack-distributed"; do
  [ -f "$c" ] && BIN="$c" && break
done
[ -n "$BIN" ] || die "built binary not found under $BUILD_DIR"
# Stripping invalidates the linker's signature; arm64 macOS refuses to run an
# unsigned binary, so sign ad hoc afterwards.
STRIPPED="$BUILD_DIR/bitcrack-distributed.stripped"
cp "$BIN" "$STRIPPED"
strip -x "$STRIPPED"
codesign --force --sign - "$STRIPPED"
echo "Built $BIN (stripped, ad-hoc signed copy: $STRIPPED)"

[ "$PACKAGE" = 1 ] || exit 0

# --- package -----------------------------------------------------------------
VERSION="$(sed -n 's/^project([^)]*VERSION \([0-9][0-9.]*\).*/\1/p' "$ROOT_DIR/CMakeLists.txt" | head -1)"
[ -n "$VERSION" ] || die "cannot read the project VERSION from CMakeLists.txt"
TAG="${PKG_TAG:-v$VERSION}"
NAME="bitcrack-distributed-$TAG-macos-$ARCH-cpu"
STAGE="$BUILD_DIR/dist/$NAME"
rm -rf "$STAGE" && mkdir -p "$STAGE"
install -m 0755 "$STRIPPED" "$STAGE/bitcrack-distributed"
cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$STAGE/"
cp "$ROOT_DIR/docs/MACOS.md" "$STAGE/MACOS.md"
case "$ARCH" in arm64) MODEL="Apple Silicon (M1 or newer)" ;; *) MODEL="Intel" ;; esac
cat > "$STAGE/RUN.txt" <<RUN
bitcrack-distributed $TAG for macOS $MODEL, CPU only
Needs macOS $MACOS_MIN or newer. Nothing else to install (OpenSSL is built in).

1. Open Terminal and go to this folder:
     cd /path/to/$NAME
2. macOS blocks programs downloaded from the internet that are not notarized.
   Allow this one (once):
     xattr -dr com.apple.quarantine .
3. Check it runs:
     ./bitcrack-distributed --version
4. Start the node with the dashboard:
     ./bitcrack-distributed --cpu --dashboard --reward <your bitcoin address>

Dashboard: open http://127.0.0.1:3339/ in a browser (this Mac only).
Stop: press Ctrl+C. Config and data live in
  ~/Library/Application Support/BitCrackDistributed/
(or config.json in the folder you start the node from).
Keep node_id.json: it is your node's identity on the network.

This build is CPU only: Macs have no NVIDIA CUDA. Set "cpu_thread_count" in
config.json to limit how many cores it uses (the --power flag does not limit).
More: MACOS.md
RUN
chmod 0644 "$STAGE/README.md" "$STAGE/LICENSE" "$STAGE/MACOS.md" "$STAGE/RUN.txt"

TARBALL="$BUILD_DIR/dist/$NAME.tar.gz"
# COPYFILE_DISABLE keeps AppleDouble (._*) files out of the archive.
COPYFILE_DISABLE=1 tar -C "$BUILD_DIR/dist" -czf "$TARBALL" "$NAME"
echo "Packaged $TARBALL"
(cd "$BUILD_DIR/dist" && shasum -a 256 "$NAME.tar.gz" | tee "$NAME.tar.gz.sha256")

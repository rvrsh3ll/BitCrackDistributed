#!/usr/bin/env bash
# Cross-compile the CPU-only bitcrack-distributed CLI for Android (Termux or
# adb shell) with the Android NDK, against a static OpenSSL built from a
# pinned, checksummed source tarball.
#
# Usage: scripts/build_android.sh [build_dir]        (default: build-android)
#
# Environment:
#   ANDROID_NDK_ROOT  NDK directory (r26 or newer; tested with r28c). Also read
#                     from ANDROID_NDK_HOME / ANDROID_NDK.
#   ANDROID_ABI       arm64-v8a (default) or x86_64 (emulator).
#   ANDROID_API       minimum API level, default 29 (Android 10; runs on 14+).
#   LINK_STATIC       1 (default): fully static binary with no runtime
#                     dependencies; it also runs under qemu-aarch64 on a Linux
#                     host for quick checks. 0: regular PIE linked against the
#                     device's libc/libm/libdl.
#   PACKAGE           1: also write <build_dir>/dist/bitcrack-distributed-
#                     v<version>-android-<arch>-cli.tar.gz (binary, cacert.pem,
#                     README.md, ANDROID.md, RUN.txt, LICENSE).
#   CACERT_PEM        CA bundle to package (default: download the Mozilla
#                     bundle from curl.se).
#   JOBS              parallel jobs (default: nproc).
#
# Requires on the host: cmake, ninja, perl, make, curl, tar, sha256sum.
# GPU (CUDA/OpenCL) is not built for Android; this is the CPU searcher.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$(realpath -m "${1:-$ROOT_DIR/build-android}")"
NDK="${ANDROID_NDK_ROOT:-${ANDROID_NDK_HOME:-${ANDROID_NDK:-}}}"
ABI="${ANDROID_ABI:-arm64-v8a}"
API="${ANDROID_API:-29}"
LINK_STATIC="${LINK_STATIC:-1}"
PACKAGE="${PACKAGE:-0}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

OPENSSL_VERSION=3.4.1
OPENSSL_SHA256=002a2d6b30b58bf4bea46c43bdd96365aaf8daa6c428782aa4feee06da197df3
OPENSSL_URL="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"
CACERT_URL="https://curl.se/ca/cacert.pem"

die() { echo "build_android.sh: $*" >&2; exit 1; }

[ -n "$NDK" ] || die "set ANDROID_NDK_ROOT to the NDK directory (e.g. /opt/android-ndk-r28c)"
[ -f "$NDK/build/cmake/android.toolchain.cmake" ] || die "$NDK does not look like an NDK (no build/cmake/android.toolchain.cmake)"
case "$ABI" in
  arm64-v8a) OSSL_TARGET=android-arm64; ARCH=arm64 ;;
  x86_64)    OSSL_TARGET=android-x86_64; ARCH=x86_64 ;;
  *) die "unsupported ANDROID_ABI=$ABI (arm64-v8a or x86_64)" ;;
esac
HOST_TAG=linux-x86_64
[ "$(uname -s)" = Darwin ] && HOST_TAG=darwin-x86_64
TOOLBIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
[ -d "$TOOLBIN" ] || die "no NDK toolchain at $TOOLBIN"

DEPS="$BUILD_DIR/deps"
# OpenSSL compiles its install paths into the library (OPENSSLDIR, MODULESDIR,
# ENGINESDIR). Configure neutral ones that do not exist on Android, so the
# binary carries no build-host paths and the node's CA fallback (TlsCa.h)
# takes over; install into a staging dir with DESTDIR.
OSSL_RUNTIME_PREFIX=/opt/openssl-android
OSSL_PREFIX="$DEPS/openssl-$OPENSSL_VERSION-$ABI-api$API$OSSL_RUNTIME_PREFIX"
mkdir -p "$DEPS"

# --- OpenSSL (static) --------------------------------------------------------
if [ ! -f "$OSSL_PREFIX/lib/libssl.a" ]; then
  tarball="$DEPS/openssl-$OPENSSL_VERSION.tar.gz"
  if [ ! -f "$tarball" ]; then
    echo "Downloading OpenSSL $OPENSSL_VERSION"
    curl -fsSL --retry 3 -o "$tarball.part" "$OPENSSL_URL"
    mv "$tarball.part" "$tarball"
  fi
  echo "$OPENSSL_SHA256  $tarball" | sha256sum -c --quiet - || die "OpenSSL tarball checksum mismatch"
  src="$DEPS/openssl-src-$ABI"
  rm -rf "$src" && mkdir -p "$src"
  tar -xzf "$tarball" -C "$src" --strip-components=1
  echo "Building OpenSSL $OPENSSL_VERSION for $OSSL_TARGET (API $API)"
  (
    cd "$src"
    export ANDROID_NDK_ROOT="$NDK" PATH="$TOOLBIN:$PATH"
    ./Configure "$OSSL_TARGET" -D__ANDROID_API__="$API" \
      no-shared no-tests no-docs no-apps no-module no-engine \
      --prefix="$OSSL_RUNTIME_PREFIX" --openssldir=/etc/ssl --libdir=lib \
      >"$DEPS/openssl-configure.log" 2>&1
    make -j"$JOBS" build_libs >"$DEPS/openssl-make.log" 2>&1
    make install_dev DESTDIR="$DEPS/openssl-$OPENSSL_VERSION-$ABI-api$API" >"$DEPS/openssl-install.log" 2>&1
  ) || die "OpenSSL build failed; see $DEPS/openssl-*.log"
fi

# --- bitcrack-distributed ----------------------------------------------------
LINKER_ARGS=()
if [ "$LINK_STATIC" = 1 ]; then
  # Bionic's static libc needs libdl.a for dlopen stubs pulled in by OpenSSL.
  LINKER_ARGS=(-DCMAKE_EXE_LINKER_FLAGS=-static -DCMAKE_CXX_STANDARD_LIBRARIES=-ldl)
fi

cmake -S "$ROOT_DIR" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI="$ABI" \
  -DANDROID_PLATFORM="android-$API" \
  -DANDROID_STL=c++_static \
  -DCMAKE_BUILD_TYPE=Release \
  "-DCMAKE_CXX_FLAGS=-ffile-prefix-map=$ROOT_DIR/=" \
  -DOPENSSL_ROOT_DIR="$OSSL_PREFIX" \
  -DOPENSSL_USE_STATIC_LIBS=TRUE \
  -DCMAKE_FIND_ROOT_PATH="$OSSL_PREFIX" \
  -DBITCRACK_DISABLE_GPU=ON \
  -DDISABLE_CUDA=ON \
  -DBITCRACK_BUILD_TESTS=OFF \
  "${LINKER_ARGS[@]}"
cmake --build "$BUILD_DIR" --target bitcrack-distributed -j "$JOBS"

BIN=""
for c in "$BUILD_DIR/bitcrack-distributed" "$BUILD_DIR/Release/bitcrack-distributed"; do
  [ -f "$c" ] && BIN="$c" && break
done
[ -n "$BIN" ] || die "built binary not found under $BUILD_DIR"
STRIPPED="$BUILD_DIR/bitcrack-distributed.stripped"
"$TOOLBIN/llvm-strip" -o "$STRIPPED" "$BIN"
echo "Built $BIN (stripped copy: $STRIPPED)"

[ "$PACKAGE" = 1 ] || exit 0

# --- package -----------------------------------------------------------------
VERSION="$(sed -n 's/^project([^)]*VERSION \([0-9][0-9.]*\).*/\1/p' "$ROOT_DIR/CMakeLists.txt" | head -1)"
[ -n "$VERSION" ] || die "cannot read the project VERSION from CMakeLists.txt"
NAME="bitcrack-distributed-v$VERSION-android-$ARCH-cli"
STAGE="$BUILD_DIR/dist/$NAME"
rm -rf "$STAGE" && mkdir -p "$STAGE"
install -m 0755 "$STRIPPED" "$STAGE/bitcrack-distributed"

if [ -n "${CACERT_PEM:-}" ]; then
  cp "$CACERT_PEM" "$STAGE/cacert.pem"
else
  curl -fsSL --retry 3 -o "$STAGE/cacert.pem" "$CACERT_URL"
fi
certs=$(grep -c 'BEGIN CERTIFICATE' "$STAGE/cacert.pem" || true)
[ "$certs" -ge 100 ] || die "cacert.pem has only $certs certificates"
chmod 0644 "$STAGE/cacert.pem"

cp "$ROOT_DIR/README.md" "$STAGE/README.md"
cp "$ROOT_DIR/docs/ANDROID.md" "$STAGE/ANDROID.md"
cp "$ROOT_DIR/LICENSE" "$STAGE/LICENSE"
cat > "$STAGE/RUN.txt" <<RUN
bitcrack-distributed v$VERSION for Android ($ABI, CPU only)

In Termux:
  chmod +x bitcrack-distributed
  termux-wake-lock
  ./bitcrack-distributed --cpu --dashboard --reward <your bitcoin address>

Dashboard: open http://127.0.0.1:3339 in the phone's browser.
Stop: Ctrl+C, then termux-wake-unlock.

cacert.pem must stay next to the binary: it is the CA bundle the node uses to
verify Electrum TLS servers. Full instructions, battery and heat advice:
ANDROID.md.
RUN
chmod 0644 "$STAGE"/*.md "$STAGE/RUN.txt" "$STAGE/LICENSE"

TARBALL="$BUILD_DIR/dist/$NAME.tar.gz"
tar -C "$BUILD_DIR/dist" --owner=0 --group=0 --numeric-owner -czf "$TARBALL" "$NAME"
echo "Packaged $TARBALL"
(cd "$BUILD_DIR/dist" && sha256sum "$NAME.tar.gz" | tee "$NAME.tar.gz.sha256")

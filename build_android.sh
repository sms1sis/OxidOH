#!/bin/bash
set -e

# ── NDK setup ─────────────────────────────────────────────────────────────────
if [ -z "$ANDROID_NDK_HOME" ]; then
    export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/29.0.14206865
fi

TOOLCHAIN=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
export PATH=$TOOLCHAIN:$PATH

TARGET="aarch64-linux-android"

# ── Argument parsing ──────────────────────────────────────────────────────────
BUILD_MODE="release"
CARGO_FLAGS="--release"
EXTRA_FEATURES=""

while getopts "dh" opt; do
  case $opt in
    d)
      BUILD_MODE="debug"
      CARGO_FLAGS=""
      echo "Building in DEBUG mode..."
      ;;
    h)
      EXTRA_FEATURES="http3"
      echo "Building with HTTP/3 support..."
      ;;
    \?)
      echo "Usage: $0 [-d] [-h]   (-d = debug build, -h = include HTTP/3)" >&2
      exit 1
      ;;
  esac
done

# ── RUSTFLAGS ─────────────────────────────────────────────────────────────────
# No target-cpu override — let LLVM use the safe ARMv8-A baseline implied by
# the aarch64-linux-android triple.  Specifying a micro-arch (e.g. cortex-a55)
# can emit instructions (RDMA, dotprod, etc.) that cause SIGILL on devices
# whose CPU doesn't implement that specific core, even if they are arm64.
# reqwest_unstable is only needed when the http3 feature is requested.
# reqwest http3 requires a compile-time cfg flag in addition to the Cargo feature.
# Unset RUSTFLAGS entirely for normal builds to avoid interfering with other tooling.
if [[ "$EXTRA_FEATURES" == *"http3"* ]]; then
    export RUSTFLAGS="--cfg reqwest_unstable"
else
    unset RUSTFLAGS
fi

# ── Tool checks ───────────────────────────────────────────────────────────────
if ! rustup target list --installed | grep -q "$TARGET"; then
    echo "Rust target $TARGET not found, adding..."
    rustup target add "$TARGET"
fi

if ! command -v cargo-ndk &> /dev/null; then
    echo "cargo-ndk not found, installing..."
    cargo install cargo-ndk
fi

# ── Version sync ──────────────────────────────────────────────────────────────
# Only update Cargo.toml if the version actually changed, to avoid dirtying git
# on every build. Warns instead of silently no-op-ing if parsing fails.
VERSION=$(grep 'versionName' android/app/build.gradle | head -1 | awk -F'"' '{print $2}')
if [ -z "$VERSION" ]; then
    echo "WARNING: could not parse versionName from build.gradle, keeping Cargo.toml version"
else
    CURRENT=$(grep '^version' Cargo.toml | head -1 | awk -F'"' '{print $2}')
    if [ "$VERSION" != "$CURRENT" ]; then
        sed -i "s/^version = \".*\"/version = \"$VERSION\"/" Cargo.toml
        echo "Version synced: $CURRENT → $VERSION"
    fi
fi

# ── Lockfile ──────────────────────────────────────────────────────────────────
# Regenerate Cargo.lock if it is missing or if Cargo.toml was just modified.
# Commit Cargo.lock to git for reproducible builds; --locked can then be added
# once the lockfile is stable.
if [ ! -f Cargo.lock ]; then
    echo "Cargo.lock not found, generating..."
    cargo generate-lockfile
fi

# ── Build ─────────────────────────────────────────────────────────────────────
# The http3 Cargo feature (which activates reqwest/http3) must be passed here;
# setting RUSTFLAGS alone is not sufficient.
FEATURES="jni"
[ -n "$EXTRA_FEATURES" ] && FEATURES="jni,$EXTRA_FEATURES"

echo "NDK:      $ANDROID_NDK_HOME"
echo "Target:   $TARGET [$BUILD_MODE]"
echo "Features: $FEATURES"
echo "--------------------------------------------------"

cargo ndk --target "$TARGET" --platform 26 build $CARGO_FLAGS --lib --features "$FEATURES"

# ── Collect output ────────────────────────────────────────────────────────────
SO_PATH="target/$TARGET/$BUILD_MODE/liboxidoh.so"
OUTPUT_DIR="android/app/src/main/jniLibs"
mkdir -p "$OUTPUT_DIR/arm64-v8a"

if [ ! -s "$SO_PATH" ]; then
    echo "ERROR: .so missing or empty at $SO_PATH" >&2
    exit 1
fi

cp "$SO_PATH" "$OUTPUT_DIR/arm64-v8a/"
echo "--------------------------------------------------"
echo "Done. $(du -h "$SO_PATH" | cut -f1) → $OUTPUT_DIR/arm64-v8a/"

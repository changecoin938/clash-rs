#!/bin/bash
set -e
set -o pipefail

IOS_ARCHS=("aarch64-apple-ios" "aarch64-apple-ios-sim")
CRATE_NAME="clash-ffi"
LIB_NAME="clashrs"
PACKAGE_NAME="LibClashRs"
OUTPUT_DIR="build"
HEADERS_DIR="${OUTPUT_DIR}/Headers"
HEADER_FILE="${HEADERS_DIR}/${LIB_NAME}/${LIB_NAME}.h"
MODULEMAP_FILE="${HEADERS_DIR}/${LIB_NAME}/module.modulemap"
XCFRAMEWORK_DIR="${OUTPUT_DIR}/${LIB_NAME}.xcframework"

TOOLCHAIN=$(cat rust-toolchain.toml 2>/dev/null | grep channel | cut -d'"' -f2 || echo "nightly")

echo "Ensuring the Rust toolchain from rust-toolchain.toml is installed..."
rustup toolchain install "$TOOLCHAIN" --profile minimal || true
echo "Using toolchain: $TOOLCHAIN"

echo "Checking for required tools..."
if ! command -v cbindgen &> /dev/null; then
    echo "cbindgen not found. Installing..."
    cargo install cbindgen
fi

echo "Installing necessary Rust targets..."
for target in "${IOS_ARCHS[@]}"; do
    rustup target add "$target" --toolchain "$TOOLCHAIN" || echo "Target $target may need local stdlib build."
done

mkdir -p "$OUTPUT_DIR"
mkdir -p "$HEADERS_DIR/${LIB_NAME}"

echo "Generating C header file..."
cbindgen --config "$CRATE_NAME/cbindgen.toml" --crate "$CRATE_NAME" --output "$HEADER_FILE"

echo "Creating modulemap..."
cat > "$MODULEMAP_FILE" <<MODEOF
module $PACKAGE_NAME {
    umbrella header "$(basename $HEADER_FILE)"
    export *
}
MODEOF

echo "Building library for iOS targets..."
for target in "${IOS_ARCHS[@]}"; do
    echo "Building for target: $target"
    IPHONEOS_DEPLOYMENT_TARGET=15.0 cargo +$TOOLCHAIN build --package "$CRATE_NAME" --target "$target" --release
    mkdir -p "$OUTPUT_DIR/$target"
    cp "target/$target/release/lib${LIB_NAME}.a" "$OUTPUT_DIR/$target/"
done

echo "Creating XCFramework..."
rm -rf "$XCFRAMEWORK_DIR"
xcodebuild -create-xcframework \
    -library "$OUTPUT_DIR/aarch64-apple-ios/lib${LIB_NAME}.a" -headers "$HEADERS_DIR" \
    -library "$OUTPUT_DIR/aarch64-apple-ios-sim/lib${LIB_NAME}.a" -headers "$HEADERS_DIR" \
    -output "$XCFRAMEWORK_DIR"

echo "XCFramework created at $XCFRAMEWORK_DIR"

echo "Cleaning up intermediate files..."
find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 ! -name "$(basename $XCFRAMEWORK_DIR)" -exec rm -rf {} +

echo "Done!"

#!/bin/bash
# Build covfuzz linked in-process with a coverage-instrumented pdftotext.
#
# Env:
#   XPDF_DIR   path to the xpdf-4.06 source tree (default: ./xpdf-4.06)
#   BUILD_DIR  build directory (default: $XPDF_DIR/cov_build)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
XPDF="${XPDF_DIR:-$ROOT/xpdf-4.06}"

if [ ! -d "$XPDF/xpdf" ]; then
  echo "Error: xpdf source not found at $XPDF"
  echo "Download xpdf-4.06 from https://www.xpdfreader.com/download.html and extract it"
  echo "into the repo root, or set XPDF_DIR=/path/to/xpdf-4.06."
  exit 1
fi
XPDF="$(cd "$XPDF" && pwd)"

XPDF_CMAKE="$XPDF/xpdf/CMakeLists.txt"
if [ ! -f "$XPDF_CMAKE" ]; then
  echo "Error: $XPDF_CMAKE not found"
  exit 1
fi

# Hook our target into xpdf's CMake project (once).
if ! grep -q "covfuzz" "$XPDF_CMAKE" 2>/dev/null; then
  echo "Patching $XPDF_CMAKE to add the covfuzz target..."
  cp "$XPDF_CMAKE" "$XPDF_CMAKE.bak"
  {
    echo ""
    echo "# covfuzz"
    echo "include(\"$ROOT/cmake/fuzzer.cmake\")"
  } >> "$XPDF_CMAKE"
fi

# Reuse whatever extra libraries xpdf links pdftotext against.
_RAW=$(awk '/target_link_libraries\s*\(\s*pdftotext/,/\)/' "$XPDF_CMAKE" | tr -d '\n' | sed 's/.*pdftotext[[:space:]]*//' | sed 's/).*//')
PDFTOTEXT_LIBS=$(echo "$_RAW" | tr ' ' '\n' | grep -E '^[A-Za-z_][A-Za-z0-9_-]*$' | tr '\n' ' ' | xargs || true)
[ -z "$PDFTOTEXT_LIBS" ] && PDFTOTEXT_LIBS="goo fofi"

BUILD_DIR="${BUILD_DIR:-$XPDF/cov_build}"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

echo "Configuring with coverage instrumentation..."
cmake "$XPDF" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-fsanitize-coverage=inline-8bit-counters" \
  -DCMAKE_CXX_FLAGS="-fsanitize-coverage=inline-8bit-counters" \
  -DOPI_SUPPORT=OFF \
  -DMULTITHREADED=ON \
  -DFUZZER_SRC="$ROOT/src/fuzzer.c" \
  -DPDFTOTEXT_LINK_LIBS="$PDFTOTEXT_LIBS"

echo "Building covfuzz..."
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
cmake --build . --target covfuzz -j"$JOBS"

FUZZER_BIN="$BUILD_DIR/xpdf/covfuzz"
if [ -f "$FUZZER_BIN" ]; then
  echo "Success: $FUZZER_BIN"
else
  echo "Build failed: $FUZZER_BIN not found"
  exit 1
fi

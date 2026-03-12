#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/build/releases}"
GO_CMD="${GO:-go}"
CMD_PATH="${CMD_PATH:-./cmd/intratun}"
VERSION="$($GO_CMD run "$CMD_PATH" version | tr -d '\r')"
RELEASE_DIR="$OUTPUT_DIR/$VERSION"

mkdir -p "$RELEASE_DIR"
rm -f "$RELEASE_DIR"/SHA256SUMS

targets=(
  "linux amd64"
  "linux arm64"
  "darwin arm64"
  "windows amd64"
)

for target in "${targets[@]}"; do
  read -r goos goarch <<<"$target"
  suffix=""
  if [[ "$goos" == "windows" ]]; then
    suffix=".exe"
  fi
  output="$RELEASE_DIR/intratun-$goos-$goarch$suffix"
  echo "Building $output"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" "$GO_CMD" build -trimpath -ldflags="-s -w" -o "$output" "$CMD_PATH"
done

(
  cd "$RELEASE_DIR"
  shasum -a 256 intratun-* > SHA256SUMS
)

echo "Release artifacts written to $RELEASE_DIR"

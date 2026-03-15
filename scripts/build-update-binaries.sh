#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/bin}"
GO_CMD="${GO:-go}"
CMD_PATH="${CMD_PATH:-./cmd/intratun}"

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/intratun-* "$OUTPUT_DIR"/SHA256SUMS

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
  output="$OUTPUT_DIR/intratun-$goos-$goarch$suffix"
  echo "Building $output"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" "$GO_CMD" build -trimpath -ldflags="-s -w" -o "$output" "$CMD_PATH"
done

(
  cd "$OUTPUT_DIR"
  shasum -a 256 intratun-* > SHA256SUMS
)

echo "Update artifacts written to $OUTPUT_DIR"

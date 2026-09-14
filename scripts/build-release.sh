#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-v1.0.0}"
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DIST_DIR="dist"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

LDFLAGS="-s -w -X main.Version=${VERSION} -X main.CommitSHA=${COMMIT} -X main.BuildDate=${BUILD_DATE}"

echo "=================================================="
echo " Building URL Proxy Release Packages: ${VERSION}"
echo " Commit: ${COMMIT} | Date: ${BUILD_DATE}"
echo "=================================================="

for PLATFORM in "${PLATFORMS[@]}"; do
  GOOS="${PLATFORM%/*}"
  GOARCH="${PLATFORM#*/}"
  BIN_NAME="url-proxy"
  EXT=""
  if [ "$GOOS" = "windows" ]; then
    EXT=".exe"
  fi

  OUTPUT_DIR="build_${GOOS}_${GOARCH}"
  mkdir -p "$OUTPUT_DIR"

  echo "==> Compiling for $GOOS/$GOARCH..."
  CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="$LDFLAGS" -o "${OUTPUT_DIR}/${BIN_NAME}${EXT}" .
  cp README.md "${OUTPUT_DIR}/" 2>/dev/null || true

  ARCHIVE_NAME="url-proxy_${VERSION}_${GOOS}_${GOARCH}"
  if [ "$GOOS" = "windows" ]; then
    if command -v zip >/dev/null 2>&1; then
      (cd "$OUTPUT_DIR" && zip -q -r "../${DIST_DIR}/${ARCHIVE_NAME}.zip" .)
    else
      python3 -c "import zipfile, os; z = zipfile.ZipFile('${DIST_DIR}/${ARCHIVE_NAME}.zip', 'w', zipfile.ZIP_DEFLATED); [z.write(os.path.join('${OUTPUT_DIR}', f), f) for f in os.listdir('${OUTPUT_DIR}')]; z.close()"
    fi
  else
    tar -czf "${DIST_DIR}/${ARCHIVE_NAME}.tar.gz" -C "$OUTPUT_DIR" .
  fi
  rm -rf "$OUTPUT_DIR"
done

cd "$DIST_DIR"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum * > checksums.txt
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 * > checksums.txt
fi
echo "==> Build complete. Checksums:"
cat checksums.txt

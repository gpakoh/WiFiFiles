#!/bin/sh
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/build"
mkdir -p "$OUT"
"$ROOT/build.sh" "$OUT"
VERSION="$(sed -n 's/^const version = "\([^"]*\)"/\1/p' "$ROOT/server.go" | head -1)"
[ -n "$VERSION" ] || { echo "version not found in server.go" >&2; exit 1; }
ZIP="$OUT/WiFiFiles_$VERSION.zip"
rm -f "$ZIP"
(cd "$OUT" && mkdir -p zip/app && cp -f WiFiFiles.app zip/app/WiFiFiles.app && cd zip && zip -qr "$ZIP" app && cd .. && rm -rf zip)
SHA256SUM="${SHA256SUM:-sha256sum}"
"$SHA256SUM" "$ZIP" > "$OUT/WiFiFiles_$VERSION.sha256"
echo "created $ZIP"
cat "$OUT/WiFiFiles_$VERSION.sha256"

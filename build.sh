#!/bin/sh
set -eu
OUT="${1:-build}"
mkdir -p "$OUT"
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 go build -trimpath -ldflags='-s -w' -o "$OUT/WiFiFiles.server" server.go mobile.go webdav.go webdav_ui.go qr.go ftp.go smb.go filenames.go library.go auth.go logging.go paths.go upload.go update.go
CLANG="${CLANG:-clang}"
CFLAGS='--target=arm-linux-gnueabi -march=armv5te -mfloat-abi=soft -Os -fno-builtin -fno-stack-protector -fno-unwind-tables -fno-asynchronous-unwind-tables -ffreestanding -fPIC'
$CLANG $CFLAGS -c inkview_stub.c -o "$OUT/inkview_stub.o"
$CLANG --target=arm-linux-gnueabi -fuse-ld=lld -nostdlib -shared "$OUT/inkview_stub.o" -Wl,-soname,libinkview.so -o "$OUT/libinkview.so"
$CLANG $CFLAGS -c native_app.c -o "$OUT/native_app.o"
$CLANG --target=arm-linux-gnueabi -fuse-ld=lld -nostdlib -no-pie -Wl,-e,_start -Wl,--dynamic-linker=/lib/ld-linux.so.3 -L"$OUT" -Wl,--no-as-needed -linkview "$OUT/native_app.o" -o "$OUT/WiFiFiles.app.base"
python3 - "$OUT/WiFiFiles.app.base" "$OUT/WiFiFiles.server" "$OUT/WiFiFiles.app" <<'PY'
import struct, sys
from pathlib import Path
base, server, out = map(Path, sys.argv[1:])
payload = server.read_bytes()
footer = b"WFSRV722" + struct.pack("<II", len(payload), len(payload) ^ 0xA55AA55A)
out.write_bytes(base.read_bytes() + payload + footer)
out.chmod(0o755)
PY

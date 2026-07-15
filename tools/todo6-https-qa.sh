#!/usr/bin/env bash
set -euo pipefail

root=$(mktemp -d /tmp/dnfast-t6-https.XXXXXX)
binary=${DNFAST_BIN:-target/debug/dnfast}
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  rm -rf "$root"
}
trap cleanup EXIT

mkdir -p "$root"/{meta,bad,good}/repodata "$root/repos" "$root/cache"
cp fixtures/rpm/generated-build10/repos/main/repodata/{repomd.xml,primary.xml.zst,filelists.xml.zst} "$root/good/repodata/"
cp "$root/good/repodata/repomd.xml" "$root/bad/repodata/"
cp "$root/good/repodata/primary.xml.zst" "$root/bad/repodata/"
printf corrupt >"$root/bad/repodata/filelists.xml.zst"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$root/ca-key.pem" -out "$root/ca.pem" -subj '/CN=dnfast Todo6 CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$root/key.pem" -out "$root/leaf.csr" -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost' >/dev/null 2>&1
openssl x509 -req -in "$root/leaf.csr" -CA "$root/ca.pem" -CAkey "$root/ca-key.pem" -CAcreateserial -days 1 -out "$root/cert.pem" -copy_extensions copy >/dev/null 2>&1

repomd_sha=$(sha256sum "$root/good/repodata/repomd.xml" | cut -d' ' -f1)
repomd_size=$(stat -c %s "$root/good/repodata/repomd.xml")
sed -e "s/@SHA@/$repomd_sha/" -e "s/@SIZE@/$repomd_size/" >"$root/meta/metalink.xml" <<'EOF'
<metalink xmlns="http://www.metalinker.org/"><file name="repomd.xml"><hash type="sha256">@SHA@</hash><size>@SIZE@</size><url preference="100">https://localhost:18444/repodata/repomd.xml</url><url preference="90">https://localhost:18445/repodata/repomd.xml</url></file></metalink>
EOF

for spec in "18443 meta" "18444 bad" "18445 good"; do
  read -r port directory <<<"$spec"
  (cd "$root/$directory" && exec openssl s_server -accept "$port" -cert "$root/cert.pem" -key "$root/key.pem" -WWW -quiet) >"$root/server-$port.log" 2>&1 &
  pids+=("$!")
done
sleep 1
printf '[local]\nmetalink=https://localhost:18443/metalink.xml\nsslverify=true\nproxy=_none_\n' >"$root/repos/local.repo"
SSL_CERT_FILE="$root/ca.pem" "$binary" repo refresh --repo-dir "$root/repos" --repo local --cache-dir "$root/cache" --releasever 44 --basearch aarch64
object_count=$(find "$root/cache/objects/sha256" -mindepth 1 -maxdepth 1 -type d | wc -l)
staging_count=$(find "$root/cache" \( -name '.staging-*' -o -name '*.tmp' \) | wc -l)
test "$object_count" -eq 1
test "$staging_count" -eq 0
printf 'objects=%s staging=%s\n' "$object_count" "$staging_count"

cat >"$root/redirect.py" <<'PY'
import socket, ssl, sys
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", 18446))
listener.listen(1)
with context.wrap_socket(listener.accept()[0], server_side=True) as peer:
    peer.recv(4096)
    peer.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://downgrade.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
PY
python3 "$root/redirect.py" "$root/cert.pem" "$root/key.pem" >"$root/redirect.log" 2>&1 &
pids+=("$!")
sleep 1
printf '[redirect]\nbaseurl=https://localhost:18446\nsslverify=true\nproxy=_none_\n' >"$root/repos/redirect.repo"
if SSL_CERT_FILE="$root/ca.pem" "$binary" repo refresh --repo-dir "$root/repos" --repo redirect --cache-dir "$root/cache" --releasever 44 --basearch aarch64; then exit 1; fi

#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT=${1:-"$ROOT/fixtures/rpm/generated"}

if [[ ${DNFAST_FIXTURE_GUEST:-0} == 1 ]]; then
  exec "$ROOT/fixtures/rpm/build-in-guest.sh" "$OUTPUT"
fi

export DNFAST_FIXTURE_BUILD=1
export DNFAST_FIXTURE_OUTPUT="$OUTPUT"
HARNESS=$(mktemp "$ROOT/tools/.fixture-harness.XXXXXX.sh")
sed '$d' "$ROOT/tools/fedora44-native-build.sh" >"$HARNESS"
set -- --keep-cache
source "$HARNESS"

finish() {
  local status=$?
  rm -f "$HARNESS"
  if ((status != 0)) && [[ -f $RUNTIME/serial.log ]]; then cp "$RUNTIME/serial.log" "$WORK/last-serial.log"; fi
  cleanup "$RUNTIME"
  ((KEEP_CACHE)) || rm -rf "$WORK/staging"
  exit "$status"
}
trap finish EXIT INT TERM HUP

build_guest() {
  local packages='rpm-build-6.0.1-2.fc44.aarch64 rpm-sign-6.0.1-2.fc44.aarch64 createrepo_c-1.2.1-5.fc44.aarch64 gnupg2-2.4.9-16.fc44.aarch64'
  guest "sudo dnf5 --assumeyes --repofrompath=locked,file:///tmp/rpms --repo=locked --setopt=locked.gpgcheck=1 --setopt=locked.gpgkey=file:///tmp/fedora44-only.gpg --setopt=install_weak_deps=False install --allowerasing $packages >/tmp/dnf-install.log && mkdir -p /home/fedora/src && tar -C /home/fedora/src -xzf /tmp/source.tar.gz && cd /home/fedora/src && DNFAST_FIXTURE_GUEST=1 tools/build-fixture-repo.sh /home/fedora/out"
  rm -rf "$OUTPUT"
  timeout 600 scp -q -r -i "$RUNTIME/id_ed25519" -P "$PORT" -o ConnectTimeout=5 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null fedora@127.0.0.1:/home/fedora/out "$OUTPUT"
}

main_build
rm -f "$HARNESS"

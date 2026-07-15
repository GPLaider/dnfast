#!/usr/bin/env bash
set -euo pipefail

FEDORA44_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FEDORA44_EVIDENCE="$FEDORA44_ROOT/.omo/evidence"
FEDORA44_URL_LOCK=${FEDORA44_URL_LOCK:-"$FEDORA44_EVIDENCE/fedora44-build-qemu-closure-urls.lock"}
FEDORA44_HASH_LOCK=${FEDORA44_HASH_LOCK:-"$FEDORA44_EVIDENCE/fedora44-build-qemu-closure.lock"}
FEDORA44_TOP_LOCK=${FEDORA44_TOP_LOCK:-"$FEDORA44_EVIDENCE/fedora44-top-level-rpm-lock.txt"}
FEDORA44_TOP_URLS=${FEDORA44_TOP_URLS:-"$FEDORA44_EVIDENCE/fedora44-top-level-rpm-urls.txt"}
FEDORA44_URL_LOCK_SHA256=${FEDORA44_URL_LOCK_SHA256:-1e239d4cd6999335f1dba377ba934b43055d312a5865e20dabc4750e6e5b011c}
FEDORA44_HASH_LOCK_SHA256=${FEDORA44_HASH_LOCK_SHA256:-a017071411619004426247080751d3b11ee1736dfa733fce76139981eeb1a057}
FEDORA44_FINGERPRINT=36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6
FEDORA44_IMAGE=Fedora-Cloud-Base-Generic-44-1.7.aarch64.qcow2
FEDORA44_IMAGE_SHA256=55c60a3b80d3616a08705afd0459e75fe9f03c54aba7a46e4002a41a72fa0d5b
FEDORA44_IMAGE_SIZE=528154624
FEDORA44_IMAGE_BASE=https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/aarch64/images

die() { echo "fedora44-vm: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "required command missing: $1"; }

validate_url_row() {
  local hash=$1 filename=$2 url=$3 host path
  [[ $hash =~ ^[0-9a-f]{64}$ ]] || die "invalid SHA-256: $hash"
  [[ $filename != */* && $filename == *.rpm ]] || die "invalid RPM filename: $filename"
  [[ $url == https://* ]] || die "non-HTTPS URL: $url"
  host=${url#https://}; host=${host%%/*}; path=/${url#https://*/}
  case "$host" in
    ftp.yz.yamagata-u.ac.jp)
      [[ $path == /pub/linux/fedora-projects/fedora/linux/releases/44/Everything/aarch64/os/Packages/* ]] || die "unlocked Fedora path: $url" ;;
    mirrors.tuna.tsinghua.edu.cn)
      [[ $path == /fedora/updates/44/Everything/aarch64/Packages/* ]] || die "unlocked updates path: $url" ;;
    *) die "unapproved URL host: $host" ;;
  esac
  [[ ${url##*/} == "$filename" ]] || die "URL filename mismatch: $filename"
}

validate_locks() {
  local actual rows hash filename url
  [[ $(sha256sum "$FEDORA44_URL_LOCK" | awk '{print $1}') == "$FEDORA44_URL_LOCK_SHA256" ]] || die "URL lock digest mismatch"
  [[ $(sha256sum "$FEDORA44_HASH_LOCK" | awk '{print $1}') == "$FEDORA44_HASH_LOCK_SHA256" ]] || die "hash lock digest mismatch"
  rows=$(wc -l <"$FEDORA44_URL_LOCK"); [[ $rows -eq 675 ]] || die "URL lock must contain exactly 675 rows"
  while read -r hash filename url extra; do
    [[ -z ${extra:-} ]] || die "extra URL lock field"
    validate_url_row "$hash" "$filename" "$url"
  done <"$FEDORA44_URL_LOCK"
  actual=$(mktemp)
  awk '!/^#/ && NF {print $1 "  " $2}' "$FEDORA44_HASH_LOCK" >"$actual"
  [[ $(wc -l <"$actual") -eq 675 ]] || die "hash lock must contain exactly 675 rows"
  awk '{print $1 "  " $2}' "$FEDORA44_URL_LOCK" | cmp -s - "$actual" || { rm -f "$actual"; die "closure locks disagree"; }
  rm -f "$actual"
  validate_top_level
}

validate_top_level() {
  local lock="$FEDORA44_TOP_LOCK" urls="$FEDORA44_TOP_URLS"
  local name nevra repo url filename hash expected expected_url
  [[ $(awk '!/^#/ && NF' "$lock" | wc -l) -eq 14 ]] || die "top-level hash index must contain 14 rows"
  [[ $(awk '!/^#/ && NF' "$urls" | wc -l) -eq 14 ]] || die "top-level URL index must contain 14 rows"
  while IFS='|' read -r name nevra repo url; do
    [[ $name == \#* || -z $name ]] && continue
    filename=${url##*/}; hash=$(awk -v f="$filename" '$2==f {print $1}' "$lock")
    expected=$(awk -v f="$filename" '$2==f {print $1}' "$FEDORA44_URL_LOCK")
    expected_url=$(awk -v f="$filename" '$2==f {print $3}' "$FEDORA44_URL_LOCK")
    [[ -n $hash && $hash == "$expected" ]] || die "top-level closure mismatch: $name"
    [[ $url == "$expected_url" ]] || die "top-level URL mismatch: $name"
    validate_url_row "$hash" "$filename" "$url"
    [[ "$name-${nevra#*:}.rpm" == "$filename" ]] || die "top-level NEVRA mismatch: $name"
    [[ $repo == fedora || $repo == updates ]] || die "invalid top-level repository"
  done <"$urls"
}

preflight() {
  local machine=${FEDORA44_UNAME_M:-$(uname -m)} kvm=${FEDORA44_KVM:-/dev/kvm}
  [[ $machine == aarch64 ]] || die "aarch64 host required, got $machine"
  [[ -c $kvm && -r $kvm && -w $kvm ]] || die "readable/writable KVM device required: $kvm"
  for cmd in curl sha256sum gpg rpm rpmkeys rpm2archive tar timeout; do need "$cmd"; done
  validate_locks
}

fetch() {
  local url=$1 output=$2
  mkdir -p "$(dirname "$output")"
  curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 300 --retry 2 --retry-delay 2 --output "$output.part" "$url"
  mv "$output.part" "$output"
}

prepare_key() {
  local work=$1 key home inspect count
  key="$work/fedora44.gpg"; home="$work/gnupg"; inspect="$work/inspect-gnupg"
  rm -rf "$home" "$inspect"; mkdir -m 700 -p "$home" "$inspect"
  fetch https://fedoraproject.org/fedora.gpg "$key"
  GNUPGHOME="$inspect" gpg --batch --quiet --import "$key"
  count=$(GNUPGHOME="$inspect" gpg --batch --with-colons --fingerprint | awk -F: -v want="$FEDORA44_FINGERPRINT" '$1=="pub" {primary=1; next} primary && $1=="fpr" {if ($10==want) found++; primary=0} END {print found+0}')
  [[ $count -eq 1 ]] || die "Fedora certificate fingerprint mismatch"
  GNUPGHOME="$inspect" gpg --batch --quiet --armor --export "$FEDORA44_FINGERPRINT" >"$work/fedora44-only.gpg"
  GNUPGHOME="$home" gpg --batch --quiet --import "$work/fedora44-only.gpg"
  rm -rf "$inspect"
}

verify_rpm() {
  local rpm_file=$1 expected_hash=$2 expected_filename=$3 keyroot=$4 queried
  [[ $(sha256sum "$rpm_file" | awk '{print $1}') == "$expected_hash" ]] || die "RPM digest mismatch: $expected_filename"
  rpmkeys --define '_keyring fs' --define "_keyringpath $keyroot/keys" --define "_rpmlock_path $keyroot/.lock" --checksig --verbose "$rpm_file" >/dev/null || die "RPM signature/integrity failure: $expected_filename"
  queried=$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}.rpm' "$rpm_file")
  [[ $queried == "$expected_filename" ]] || die "RPM header NEVRA/arch mismatch: $expected_filename != $queried"
  [[ $queried == *.aarch64.rpm || $queried == *.noarch.rpm ]] || die "RPM architecture rejected: $queried"
}

download_closure() {
  local work=$1 cache keyroot hash filename url rpm_file
  cache="$work/rpms"; keyroot="$work/rpmkeys"
  validate_locks; prepare_key "$work"; mkdir -p "$cache" "$keyroot"
  rpmkeys --define '_keyring fs' --define "_keyringpath $keyroot/keys" --define "_rpmlock_path $keyroot/.lock" --import "$work/fedora44-only.gpg"
  [[ $(find "$keyroot/keys" -type f | wc -l) -eq 1 ]] || die "isolated RPM keyring cardinality mismatch"
  [[ $(basename "$(find "$keyroot/keys" -type f)") == "gpg-pubkey-${FEDORA44_FINGERPRINT,,}.key" ]] || die "isolated RPM keyring fingerprint mismatch"
  while read -r hash filename url; do
    rpm_file="$cache/$filename"
    [[ -f $rpm_file ]] || fetch "$url" "$rpm_file"
    verify_rpm "$rpm_file" "$hash" "$filename" "$keyroot"
  done <"$FEDORA44_URL_LOCK"
}

extract_closure() {
  local work=$1 root=$2 hash filename url
  mkdir -p "$root"
  while read -r hash filename url; do
    find "$root" -type d ! -perm -u=w -exec chmod u+w {} +
    rpm2archive "$work/rpms/$filename" | tar -xz --no-same-owner --no-same-permissions -C "$root"
  done <"$FEDORA44_URL_LOCK"
}

verify_image() {
  local work=$1 image checksum
  image="$work/$FEDORA44_IMAGE"; checksum="$work/Fedora-Cloud-44-1.7-aarch64-CHECKSUM"
  [[ -f $work/fedora44-only.gpg ]] || prepare_key "$work"
  [[ -f $image ]] || fetch "$FEDORA44_IMAGE_BASE/$FEDORA44_IMAGE" "$image"
  [[ -f $checksum ]] || fetch "$FEDORA44_IMAGE_BASE/Fedora-Cloud-44-1.7-aarch64-CHECKSUM" "$checksum"
  GNUPGHOME="$work/gnupg" gpg --batch --status-fd 1 --verify "$checksum" 2>/dev/null | awk -v want="$FEDORA44_FINGERPRINT" '$2=="VALIDSIG" && ($3==want || $NF==want) {valid=1} END {exit !valid}' || die "Cloud CHECKSUM signature rejected"
  [[ $(stat -c %s "$image") -eq $FEDORA44_IMAGE_SIZE ]] || die "Cloud image size mismatch"
  [[ $(sha256sum "$image" | awk '{print $1}') == "$FEDORA44_IMAGE_SHA256" ]] || die "Cloud image digest mismatch"
  grep -F "$FEDORA44_IMAGE_SHA256" "$checksum" | grep -Fq "$FEDORA44_IMAGE" || die "pinned image absent from signed CHECKSUM"
}

cleanup() {
  local runtime=$1 pid i
  if [[ -f $runtime/qemu.pid ]]; then
    pid=$(cat "$runtime/qemu.pid"); kill "$pid" 2>/dev/null || true
    for i in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf -- "$runtime"
}

main() {
  case ${1:-} in
    validate-locks) validate_locks ;;
    validate-url-row) shift; validate_url_row "$@" ;;
    preflight) preflight ;;
    download) download_closure "${2:?work directory required}" ;;
    extract) extract_closure "${2:?work directory required}" "${3:?tool root required}" ;;
    verify-image) verify_image "${2:?work directory required}" ;;
    cleanup) cleanup "${2:?runtime directory required}" ;;
    *) die "usage: $0 {validate-locks|validate-url-row HASH FILE URL|preflight|download WORK|extract WORK ROOT|verify-image WORK|cleanup DIR}" ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi

#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARCH=
BASEURL=
REPOSITORY_ID=main
REPOSITORY_FINGERPRINT=
REPOSITORY_KEY="$ROOT/fixtures/rpm/generated-build10/keys/allowed.asc"
WORK=${FEDORA44_WORK:-"$ROOT/.cache/fedora44-vm"}
RECEIPT=
RUN=0
GUEST_FIXTURE=0
RUNTIME=
PORT=
QEMU_PID=
QEMU_SYSTEM=
QEMU_IMG=
CLOUD_LOCALDS=
IMAGE=
FIRMWARE=
VARIABLES=
RPM_REPOSITORY=
CREATEREPO=
BUILD_GPG_KEY=
TOOL_LIBRARY_PATH=
SOURCE_MANIFEST=
SOURCE_MANIFEST_SHA256=

usage() {
  printf '%s\n' "usage: $0 --arch {aarch64|x86_64} --baseurl HTTPS_URL --fingerprint FINGERPRINT [--repo ID] [--key FILE] [--work DIR] [--receipt FILE] [--guest-fixture] [--run]"
}

die() {
  printf 'public-qemu-matrix: %s\n' "$*" >&2
  exit 1
}

require_file() {
  [[ -f $1 ]] || die "required file is absent: $1"
}

require_executable() {
  [[ -x $1 ]] || die "required executable is absent: $1"
}

record() {
  printf '%s\n' "$1"
  if [[ -n $RECEIPT ]]; then
    printf '%s\n' "$1" >>"$RECEIPT"
  fi
}

parse_request() {
  while (($#)); do
    case $1 in
      --arch) shift; ARCH=${1:?--arch requires an architecture} ;;
      --baseurl) shift; BASEURL=${1:?--baseurl requires an HTTPS URL} ;;
      --repo) shift; REPOSITORY_ID=${1:?--repo requires an identifier} ;;
      --fingerprint) shift; REPOSITORY_FINGERPRINT=${1:?--fingerprint requires a primary fingerprint} ;;
      --key) shift; REPOSITORY_KEY=${1:?--key requires a certificate file} ;;
      --work) shift; WORK=${1:?--work requires a directory} ;;
      --receipt) shift; RECEIPT=${1:?--receipt requires a file} ;;
      --guest-fixture) GUEST_FIXTURE=1 ;;
      --run) RUN=1 ;;
      --help|-h) usage; exit 0 ;;
      *) usage >&2; exit 2 ;;
    esac
    shift
  done
}

validate_request() {
  [[ $ARCH == aarch64 || $ARCH == x86_64 ]] || die "unsupported architecture: $ARCH"
  [[ $BASEURL == https://* ]] || die "repository base URL must use HTTPS"
  [[ $REPOSITORY_ID =~ ^[A-Za-z0-9_.-]+$ ]] || die "repository identifier is invalid"
  [[ $REPOSITORY_FINGERPRINT =~ ^[[:xdigit:]]{40}$ ]] || die "repository fingerprint must be a 40-hex primary fingerprint"
  require_file "$REPOSITORY_KEY"
  if ((GUEST_FIXTURE)); then
    [[ $BASEURL == https://localhost:18443 ]] || die "--guest-fixture requires --baseurl https://localhost:18443"
  fi
}

native_kvm_preflight() {
  local host_arch
  host_arch=$(uname -m)
  case $ARCH in
    aarch64) [[ $host_arch == aarch64 ]] || die "aarch64 KVM host required, got $host_arch" ;;
    x86_64) [[ $host_arch == x86_64 ]] || die "x86_64 KVM host required, got $host_arch" ;;
  esac
  [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || die "readable/writable KVM device required: /dev/kvm"
}

set_architecture_defaults() {
  case $ARCH in
    aarch64)
      QEMU_SYSTEM=${MATRIX_QEMU_SYSTEM:-"$WORK/toolroot/usr/bin/qemu-system-aarch64"}
      QEMU_IMG=${MATRIX_QEMU_IMG:-"$WORK/toolroot/usr/bin/qemu-img"}
      CLOUD_LOCALDS=${MATRIX_CLOUD_LOCALDS:-"$WORK/toolroot/usr/bin/cloud-localds"}
      IMAGE=${MATRIX_IMAGE:-"$WORK/Fedora-Cloud-Base-Generic-44-1.7.aarch64.qcow2"}
      FIRMWARE=${MATRIX_FIRMWARE:-"$(find "$WORK/toolroot" -type f -path '*/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw' -print -quit)"}
      VARIABLES=${MATRIX_VARIABLES:-"$(find "$WORK/toolroot" -type f -path '*/usr/share/edk2/aarch64/vars-template-pflash.raw' -print -quit)"}
      RPM_REPOSITORY=${MATRIX_RPM_REPOSITORY:-"$WORK/rpms"}
      CREATEREPO=${MATRIX_CREATEREPO:-"$WORK/toolroot/usr/bin/createrepo_c"}
      BUILD_GPG_KEY=${MATRIX_BUILD_GPG_KEY:-"$WORK/fedora44-only.gpg"}
      TOOL_LIBRARY_PATH=${MATRIX_TOOL_LIBRARY_PATH:-"$WORK/toolroot/usr/lib64:$WORK/toolroot/usr/lib"}
      ;;
    x86_64)
      QEMU_SYSTEM=${MATRIX_QEMU_SYSTEM:-}
      QEMU_IMG=${MATRIX_QEMU_IMG:-}
      CLOUD_LOCALDS=${MATRIX_CLOUD_LOCALDS:-}
      IMAGE=${MATRIX_IMAGE:-}
      FIRMWARE=${MATRIX_FIRMWARE:-}
      VARIABLES=${MATRIX_VARIABLES:-}
      RPM_REPOSITORY=${MATRIX_RPM_REPOSITORY:-}
      CREATEREPO=${MATRIX_CREATEREPO:-}
      BUILD_GPG_KEY=${MATRIX_BUILD_GPG_KEY:-}
      TOOL_LIBRARY_PATH=${MATRIX_TOOL_LIBRARY_PATH:-}
      ;;
  esac
  require_executable "$QEMU_SYSTEM"
  require_executable "$QEMU_IMG"
  require_executable "$CLOUD_LOCALDS"
  require_file "$IMAGE"
  require_file "$FIRMWARE"
  require_file "$VARIABLES"
  [[ -d $RPM_REPOSITORY ]] || die "RPM build repository is absent: $RPM_REPOSITORY"
  require_executable "$CREATEREPO"
  require_file "$BUILD_GPG_KEY"
}

choose_port() {
  local candidate
  for candidate in $(seq 23000 23999 | shuf); do
    if ! ss -Hln "sport = :$candidate" 2>/dev/null | grep -q .; then
      PORT=$candidate
      return
    fi
  done
  die "no loopback SSH port is available"
}

cleanup_runtime() {
  local pid command_line
  [[ -n $RUNTIME ]] || return
  case $RUNTIME in
    /tmp/dnfast-public-qemu.*) ;;
    *) die "refusing cleanup outside the owned runtime prefix: $RUNTIME" ;;
  esac
  if [[ -f $RUNTIME/qemu.pid ]]; then
    pid=$(<"$RUNTIME/qemu.pid")
    if [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      command_line=$(tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null || true)
      if [[ $command_line == *"$RUNTIME/overlay.qcow2"* ]]; then
        kill "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
        if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
      fi
    fi
  fi
  rm -rf -- "$RUNTIME"
  RUNTIME=
  record 'qmp_cleanup=completed'
  record 'pid_cleanup=completed'
  record 'overlay_cleanup=completed'
}

record_failure_observation() {
  record "$1" || true
}

guest_log_capture_ready() {
  [[ -n $RECEIPT && -n $RUNTIME && $PORT =~ ^[0-9]+$ ]] || return 1
  case $RUNTIME in
    /tmp/dnfast-public-qemu.*) ;;
    *) return 1 ;;
  esac
  [[ -d $RUNTIME && ! -L $RUNTIME && -f $RUNTIME/id_ed25519 && ! -L $RUNTIME/id_ed25519 ]]
}

extract_guest_logs() {
  local log_root archive partial archive_sha256 guest_log_command
  if ! guest_log_capture_ready; then
    record_failure_observation 'public_qemu_matrix_guest_logs_status=unavailable'
    return 0
  fi

  log_root="$RECEIPT.guest-logs"
  archive="$log_root/guest-logs.tar.gz"
  partial="$log_root/.guest-logs.tar.gz.partial"
  if [[ -e $log_root ]]; then
    record_failure_observation 'public_qemu_matrix_guest_logs_status=destination_exists'
    return 0
  fi
  if ! mkdir -m 0700 -- "$log_root"; then
    record_failure_observation 'public_qemu_matrix_guest_logs_status=host_directory_failed'
    return 0
  fi

  guest_log_command=$(cat <<'EOF'
set -euo pipefail
logs=()
for log in \
  tmp/dnfast-public-build-install.log \
  tmp/dnfast-public-refresh.json \
  tmp/dnfast-public-inventory-digest.log \
  tmp/dnfast-public-managed-files-digest.log \
  tmp/dnfast-public-nonroot.log \
  tmp/dnfast-public-fixture/server.log; do
  test -f "/$log" && test ! -L "/$log" && logs+=("$log")
done
while IFS= read -r -d '' log; do
  logs+=("${log#/}")
done < <(find /home/fedora/dnfast-public-matrix -xdev -maxdepth 1 -type f \( -name '*.apply.log' -o -name '*.pty.log' -o -name '*.refresh.log' -o -name '*.plan' -o -name '*.plan.json' \) -print0)
(( ${#logs[@]} > 0 ))
tar -C / -czf - -- "${logs[@]}"
EOF
)
  if (ulimit -f 32768; guest "$guest_log_command" >"$partial"); then
    if [[ ! -s $partial ]]; then
      rm -f -- "$partial"
      rmdir -- "$log_root" 2>/dev/null || true
      record_failure_observation 'public_qemu_matrix_guest_logs_status=guest_archive_empty'
      return 0
    fi
    if ! mv -- "$partial" "$archive" || ! chmod 0600 -- "$archive"; then
      rm -f -- "$partial" "$archive"
      rmdir -- "$log_root" 2>/dev/null || true
      record_failure_observation 'public_qemu_matrix_guest_logs_status=host_publish_failed'
      return 0
    fi
    if archive_sha256=$(sha256sum "$archive" | awk '{print $1}'); then
      record_failure_observation 'public_qemu_matrix_guest_logs_status=captured'
      record_failure_observation "public_qemu_matrix_guest_logs=$archive"
      record_failure_observation "public_qemu_matrix_guest_logs_sha256=$archive_sha256"
      return 0
    fi
    rm -f -- "$archive"
    rmdir -- "$log_root" 2>/dev/null || true
    record_failure_observation 'public_qemu_matrix_guest_logs_status=host_digest_failed'
    return 0
  fi

  rm -f -- "$partial"
  rmdir -- "$log_root" 2>/dev/null || true
  record_failure_observation 'public_qemu_matrix_guest_logs_status=guest_archive_failed'
  return 0
}

finish() {
  local status=$? serial_log
  if ((status != 0)) && [[ -n $RECEIPT && -n $RUNTIME && -s $RUNTIME/serial.log ]]; then
    serial_log="$RECEIPT.serial.log"
    cp "$RUNTIME/serial.log" "$serial_log"
    record "public_qemu_matrix_serial_log=$serial_log"
    record "public_qemu_matrix_serial_log_sha256=$(sha256sum "$serial_log" | awk '{print $1}')"
  fi
  if ((status != 0)); then
    extract_guest_logs
  fi
  cleanup_runtime
  exit "$status"
}

make_seed() {
  local key=$1
  mkdir -p "$RUNTIME/seed"
  printf '%s\n' 'instance-id: dnfast-public-qemu' 'local-hostname: dnfast-public-qemu' >"$RUNTIME/seed/meta-data"
  {
    printf '%s\n' '#cloud-config' 'users:' '  - name: fedora' '    groups: [wheel]' '    sudo: ALL=(ALL) NOPASSWD:ALL' '    ssh_authorized_keys:'
    printf '      - %s\n' "$(<"$key.pub")"
    printf '%s\n' 'ssh_pwauth: false'
  } >"$RUNTIME/seed/user-data"
  "$CLOUD_LOCALDS" "$RUNTIME/seed.iso" "$RUNTIME/seed/user-data" "$RUNTIME/seed/meta-data"
}

wait_ssh() {
  local key=$1
  for _ in $(seq 1 120); do
    if timeout 3 ssh -i "$key" -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 fedora@127.0.0.1 true 2>/dev/null; then return; fi
    [[ -f $RUNTIME/qemu.pid ]] || die "QEMU PID receipt disappeared before SSH was ready"
    kill -0 "$(<"$RUNTIME/qemu.pid")" 2>/dev/null || die "QEMU exited before SSH became ready"
    sleep 1
  done
  die "guest SSH readiness timeout"
}

boot_guest() {
  local key machine
  RUNTIME=$(mktemp -d /tmp/dnfast-public-qemu.XXXXXX)
  key="$RUNTIME/id_ed25519"
  ssh-keygen -q -t ed25519 -N '' -f "$key"
  make_seed "$key"
  env LD_LIBRARY_PATH="$TOOL_LIBRARY_PATH" "$QEMU_IMG" create -q -f qcow2 -F qcow2 -b "$IMAGE" "$RUNTIME/overlay.qcow2"
  cp "$VARIABLES" "$RUNTIME/vars.raw"
  choose_port
  case $ARCH in
    aarch64) machine='virt,accel=kvm,gic-version=host' ;;
    x86_64) machine='q35,accel=kvm' ;;
  esac
  env LD_LIBRARY_PATH="$TOOL_LIBRARY_PATH" "$QEMU_SYSTEM" \
    -machine "$machine" -cpu host -smp 4 -m 4096 \
    -nodefaults -nographic -serial mon:stdio -no-reboot \
    -drive "if=pflash,format=raw,readonly=on,file=$FIRMWARE" \
    -drive "if=pflash,format=raw,file=$RUNTIME/vars.raw" \
    -drive "if=virtio,format=qcow2,file=$RUNTIME/overlay.qcow2" \
    -drive "if=virtio,format=raw,readonly=on,file=$RUNTIME/seed.iso" \
    -netdev "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:$PORT-:22" -device virtio-net-pci,netdev=n0 \
    -qmp "unix:$RUNTIME/qmp.sock,server=on,wait=off" >"$RUNTIME/serial.log" 2>&1 &
  QEMU_PID=$!
  printf '%s\n' "$QEMU_PID" >"$RUNTIME/qemu.pid"
  wait_ssh "$key"
}

guest() {
  ssh -i "$RUNTIME/id_ed25519" -p "$PORT" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 fedora@127.0.0.1 "BASHRCSOURCED=Y bash -euo pipefail -c $(printf '%q' "$1")"
}

source_manifest_from_tree() {
  local tree=$1 manifest=$2 path digest
  (
    cd "$tree"
    find . -type f -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' path; do
      case $path in
        *$'\n'*|*$'\r'*|*$'\t'*) die "archived source path is not manifest-safe: $path" ;;
      esac
      digest=$(sha256sum -- "$path" | awk '{print $1}')
      printf '%s\t%s\n' "$path" "$digest"
    done
  ) >"$manifest"
}

copy_build_inputs() {
  local archive manifest_tree staged_rpm_repository
  archive="$RUNTIME/dnfast-public-source.tar.gz"
  timeout 600 cargo vendor --manifest-path "$ROOT/Cargo.toml" --offline --locked --versioned-dirs "$RUNTIME/vendor" >/dev/null
  mkdir -p "$RUNTIME/.cargo"
  printf '%s\n' '[source.crates-io]' 'replace-with = "vendored-sources"' '[source.vendored-sources]' 'directory = "/home/fedora/src/vendor"' '[net]' 'offline = true' >"$RUNTIME/.cargo/config.toml"
  tar --exclude=.cache --exclude=target --exclude=.omo/evidence -C "$ROOT" -cf "$RUNTIME/source.tar" .
  tar -C "$RUNTIME" -rf "$RUNTIME/source.tar" vendor .cargo
  gzip "$RUNTIME/source.tar"
  mv "$RUNTIME/source.tar.gz" "$archive"
  manifest_tree=$(mktemp -d "$RUNTIME/source-manifest.XXXXXX")
  tar -C "$manifest_tree" -xzf "$archive"
  SOURCE_MANIFEST="$RUNTIME/dnfast-public-source.manifest"
  source_manifest_from_tree "$manifest_tree" "$SOURCE_MANIFEST"
  rm -rf -- "$manifest_tree"
  SOURCE_MANIFEST_SHA256=$(sha256sum "$SOURCE_MANIFEST" | awk '{print $1}')
  record "public_qemu_matrix_source_manifest_sha256=$SOURCE_MANIFEST_SHA256"
  staged_rpm_repository="$RUNTIME/rpm-repository"
  mkdir -p "$staged_rpm_repository"
  cp -a -- "$RPM_REPOSITORY/." "$staged_rpm_repository/"
  env LD_LIBRARY_PATH="$TOOL_LIBRARY_PATH" "$CREATEREPO" --no-database --simple-md-filenames "$staged_rpm_repository" >/dev/null
  scp -q -i "$RUNTIME/id_ed25519" -P "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$archive" "$SOURCE_MANIFEST" "$BUILD_GPG_KEY" fedora@127.0.0.1:/tmp/
  tar -C "$staged_rpm_repository" -cf - . | guest 'mkdir -p /tmp/dnfast-public-rpms && tar -C /tmp/dnfast-public-rpms -xf -'
}

prepare_guest_source_tree() {
  local source_check
  [[ $SOURCE_MANIFEST_SHA256 =~ ^[[:xdigit:]]{64}$ ]] || die 'source manifest digest is unavailable before guest build'
  source_check=$(cat <<'EOF'
set -e
rm -rf /home/fedora/src /tmp/dnfast-public-source.guest.manifest
mkdir -p /home/fedora/src
tar -C /home/fedora/src -xzf /tmp/dnfast-public-source.tar.gz
cd /home/fedora/src
find . -type f -print0 | LC_ALL=C sort -z | while IFS= read -r -d '' path; do
  case $path in
    *$'\n'*|*$'\r'*|*$'\t'*) exit 1 ;;
  esac
  digest=$(sha256sum -- "$path" | awk '{print $1}')
  printf '%s\t%s\n' "$path" "$digest"
done > /tmp/dnfast-public-source.guest.manifest
cmp -s /tmp/dnfast-public-source.manifest /tmp/dnfast-public-source.guest.manifest
test "$(sha256sum /tmp/dnfast-public-source.guest.manifest | awk '{print $1}')" = "$expected_source_manifest_sha256"
EOF
)
  guest "expected_source_manifest_sha256=$(printf '%q' "$SOURCE_MANIFEST_SHA256")
$source_check"
  record 'public_qemu_matrix_guest_source_manifest=verified'
}

package_public_cli() {
  local package_root=/tmp/dnfast-public-package quoted_packages
  local -a packages
  case $ARCH in
    aarch64) packages=(gcc-16.1.1-2.fc44.aarch64 libsolv-devel-0.7.39-1.fc44.aarch64 rpm-devel-6.0.1-2.fc44.aarch64 libmodulemd-devel-2.15.3-1.fc44.aarch64 pkgconf-pkg-config-2.5.1-1.fc44.aarch64 rust-1.96.1-1.fc44.aarch64 cargo-1.96.1-1.fc44.aarch64) ;;
    x86_64) read -r -a packages <<<"${MATRIX_BUILD_PACKAGES:-}"; ((${#packages[@]})) || die 'MATRIX_BUILD_PACKAGES is required for x86_64' ;;
  esac
  quoted_packages=$(printf ' %q' "${packages[@]}")
  prepare_guest_source_tree
  guest "sudo dnf5 --assumeyes --repofrompath=locked,file:///tmp/dnfast-public-rpms --repo=locked --setopt=locked.gpgcheck=1 --setopt=locked.gpgkey=file:///tmp/$(basename "$BUILD_GPG_KEY") --setopt=install_weak_deps=False install --allowerasing$quoted_packages >/tmp/dnfast-public-build-install.log; rm -rf $package_root; cd /home/fedora/src; DNFAST_NATIVE_REAL=1 cargo install --offline --locked --path crates/dnfast-cli --root $package_root; DNFAST_NATIVE_REAL=1 cargo install --offline --locked --path crates/dnfast-executor --root $package_root; sudo install -o root -g root -m 0755 $package_root/bin/dnfast /usr/bin/dnfast; sudo install -o root -g root -m 0755 $package_root/bin/dnfast-executor /usr/libexec/dnfast-executor; sudo install -o root -g root -m 0755 $package_root/bin/dnfastd /usr/libexec/dnfastd; sudo install -o root -g root -m 0644 packaging/dnfastd.service /etc/systemd/system/dnfastd.service; sudo systemctl daemon-reload"
  require_installed_public_cli
  record "public_cli_sha256=$(guest 'sha256sum /usr/bin/dnfast | awk '\''{print $1}'\''')"
}

require_installed_public_cli() {
  guest "for path in /usr/bin/dnfast /usr/libexec/dnfast-executor /usr/libexec/dnfastd; do test -f \"\$path\"; test ! -L \"\$path\"; test -x \"\$path\"; test \"\$(stat -c '%u:%g:%a:%h' \"\$path\")\" = '0:0:755:1'; done; for path in /usr/bin/dnfast /usr/libexec/dnfast-executor /usr/libexec/dnfastd; do ldd \"\$path\" | grep -F 'libsolv.so.1'; ldd \"\$path\" | grep -F 'librpm.so.10'; ldd \"\$path\" | grep -F 'libmodulemd.so.2'; done; test \"\$(stat -c '%u:%g:%a:%h' /etc/systemd/system/dnfastd.service)\" = '0:0:644:1'; /usr/bin/dnfast --help >/tmp/dnfast-public-help.json; /usr/bin/python3 -c 'import os, pty, sys; assert os.waitstatus_to_exitcode'"
}

start_guest_https_fixture() {
  ((GUEST_FIXTURE)) || return
  guest 'root=/tmp/dnfast-public-fixture; rm -rf "$root"; mkdir -p "$root"; openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$root/ca-key.pem" -out "$root/ca.pem" -subj "/CN=dnfast public fixture CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1; openssl req -newkey rsa:2048 -nodes -keyout "$root/key.pem" -out "$root/leaf.csr" -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost" >/dev/null 2>&1; openssl x509 -req -in "$root/leaf.csr" -CA "$root/ca.pem" -CAkey "$root/ca-key.pem" -CAcreateserial -days 1 -out "$root/cert.pem" -copy_extensions copy >/dev/null 2>&1; sudo install -o root -g root -m 0644 "$root/ca.pem" /etc/pki/ca-trust/source/anchors/dnfast-public-fixture-ca.pem; sudo update-ca-trust; cd /home/fedora/src/fixtures/rpm/generated-build10/repos/main; nohup openssl s_server -accept 18443 -cert "$root/cert.pem" -key "$root/key.pem" -WWW -quiet >"$root/server.log" 2>&1 </dev/null & printf "%s\n" "$!" >"$root/server.pid"; for _ in $(seq 1 30); do curl --fail --silent --show-error https://localhost:18443/repodata/repomd.xml >/dev/null && exit 0; sleep 1; done; cat "$root/server.log" >&2; exit 1'
  record 'guest_https_fixture=ready'
}

write_bootstrap_config_files() {
  local main_config_path=$1 repo_config_path=$2
  printf '%s\n' \
    '[main]' \
    'reposdir=' \
    'reposdir=/etc/dnfast-public-repos' \
    'varsdir=' \
    'varsdir=/etc/dnfast-public-vars' >"$main_config_path"
  printf '%s\n' \
    "[$REPOSITORY_ID]" \
    'name=dnfast public matrix' \
    "baseurl=$BASEURL" \
    'enabled=true' \
    'sslverify=true' \
    'gpgcheck=true' \
    'pkg_gpgcheck=true' \
    'repo_gpgcheck=false' \
    "gpgkey=/etc/dnfast/keys/$REPOSITORY_ID/matrix.asc" \
    "dnfast_allowed_fingerprints=$REPOSITORY_FINGERPRINT" >"$repo_config_path"
}

bootstrap_root_snapshot() {
  local main_config_path repo_config_path
  main_config_path="$RUNTIME/dnfast-public-dnf.conf"
  repo_config_path="$RUNTIME/dnfast-public-repository.repo"
  write_bootstrap_config_files "$main_config_path" "$repo_config_path"
  scp -q -i "$RUNTIME/id_ed25519" -P "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$REPOSITORY_KEY" fedora@127.0.0.1:/tmp/dnfast-public-matrix.asc
  scp -q -i "$RUNTIME/id_ed25519" -P "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$main_config_path" fedora@127.0.0.1:/tmp/dnfast-public-dnf.conf
  scp -q -i "$RUNTIME/id_ed25519" -P "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$repo_config_path" fedora@127.0.0.1:/tmp/dnfast-public-repository.repo
  guest "sudo install -d -o root -g root -m 0755 /etc/dnfast-public-repos /etc/dnfast-public-vars; sudo install -d -o root -g root -m 0700 /etc/dnfast/keys/$REPOSITORY_ID; sudo install -o root -g root -m 0600 /tmp/dnfast-public-matrix.asc /etc/dnfast/keys/$REPOSITORY_ID/matrix.asc; sudo install -o root -g root -m 0644 /tmp/dnfast-public-dnf.conf /etc/dnf/dnf.conf; sudo install -o root -g root -m 0644 /tmp/dnfast-public-repository.repo /etc/dnfast-public-repos/$REPOSITORY_ID.repo; if ! sudo /usr/bin/dnfast repo refresh --repo $REPOSITORY_ID >/tmp/dnfast-public-refresh.json 2>&1; then cat /tmp/dnfast-public-refresh.json >&2; exit 1; fi; test -r /var/lib/dnfast/planning/current; sudo systemctl enable --now dnfastd.service; daemon_ready=0; for _ in \$(seq 1 100); do if sudo /usr/bin/dnfast --json daemon status | grep -F 'resident_daemon=available' >/dev/null; then daemon_ready=1; break; fi; sleep 0.1; done; if test \"\$daemon_ready\" != 1; then sudo systemctl status --no-pager dnfastd.service >&2 || true; sudo journalctl --no-pager -u dnfastd.service >&2 || true; exit 1; fi"
  record 'root_snapshot_bootstrap=passed'
}

named_scenarios() {
  printf '%s\n' \
    signed_install signed_upgrade signed_remove public_pty_default_no public_pty_yes \
    nonroot verifydb before_after_sorted staging_cleanup input_cleanup \
    qmp_cleanup pid_cleanup overlay_cleanup
}

record_scenario_pass() {
  record "matrix_scenario=$1 status=passed"
}

inventory_digest() {
  guest "log=/tmp/dnfast-public-inventory-digest.log; rm -f -- \"\$log\"; install -m 0600 /dev/null \"\$log\"; test -f \"\$log\" && test ! -L \"\$log\" && test \"\$(stat -c '%u:%a:%h' \"\$log\")\" = \"\$(id -u):600:1\"; { rpm -qa | LC_ALL=C sort | sha256sum | awk '{print \$1}'; } 2>\"\$log\""
}

managed_files_digest() {
  guest "log=/tmp/dnfast-public-managed-files-digest.log; rm -f -- \"\$log\"; install -m 0600 /dev/null \"\$log\"; test -f \"\$log\" && test ! -L \"\$log\" && test \"\$(stat -c '%u:%a:%h' \"\$log\")\" = \"\$(id -u):600:1\"; { if test -e /usr/share/dnfast; then find /usr/share/dnfast -xdev -printf '%y\\t%P\\t%s\\n' | LC_ALL=C sort | sha256sum | awk '{print \$1}'; else printf absent | sha256sum | awk '{print \$1}'; fi; } 2>\"\$log\""
}

assert_staging_empty() {
  guest "if sudo test -d /var/lib/dnfast/staging; then ! sudo find /var/lib/dnfast/staging -mindepth 1 -print -quit | grep -q .; fi"
}

assert_input_preparation_clean() {
  guest "if sudo test -d /var/lib/dnfast/inputs; then ! sudo find /var/lib/dnfast/inputs -mindepth 1 -maxdepth 1 -name '.preparing-*' -print -quit | grep -q .; fi"
}

public_plan() {
  local action=$1 package=$2 name=$3
  local plan="/home/fedora/dnfast-public-matrix/$name.plan"
  if ! guest "install -d -m 0700 /home/fedora/dnfast-public-matrix; rm -f $(printf '%q' "$plan") $(printf '%q' "$plan.json"); /usr/bin/dnfast --json plan $(printf '%q' "$action") --repo $(printf '%q' "$REPOSITORY_ID") --output $(printf '%q' "$plan") $(printf '%q' "$package") >$(printf '%q' "$plan.json"); grep -F '\"status\":\"planned\"' $(printf '%q' "$plan.json") >/dev/null; test -f $(printf '%q' "$plan")"; then
    return 1
  fi
  printf '%s\n' "$plan"
}

refresh_root_snapshot() {
  local name=$1 log
  log="/home/fedora/dnfast-public-matrix/$name.refresh.log"
  if ! guest "install -d -m 0700 /home/fedora/dnfast-public-matrix; log=$(printf '%q' "$log"); rm -f -- \"\$log\"; install -m 0600 /dev/null \"\$log\"; if ! sudo /usr/bin/dnfast repo refresh --repo $(printf '%q' "$REPOSITORY_ID") >\"\$log\" 2>&1; then cat \"\$log\" >&2; exit 1; fi; test -r /var/lib/dnfast/planning/current"; then
    return 1
  fi
  record "root_snapshot_refresh=$name status=passed"
}

public_apply_yes() {
  local plan=$1 name=$2
  if ! guest "sudo /usr/bin/dnfast apply $(printf '%q' "$plan") --assumeyes >$(printf '%q' "/home/fedora/dnfast-public-matrix/$name.apply.log") 2>&1"; then
    return 1
  fi
  refresh_root_snapshot "$name"
}

public_apply_pty() {
  local plan=$1 answer=$2 name=$3 transcript input driver
  transcript="/home/fedora/dnfast-public-matrix/$name.pty.log"
  driver='import os, pty, sys; raise SystemExit(os.waitstatus_to_exitcode(pty.spawn(sys.argv[2:])))'
  case $answer in
    n|y) input=$answer ;;
    *) die "unsupported PTY approval answer: $answer" ;;
  esac
  if ! guest "install -d -m 0700 /home/fedora/dnfast-public-matrix; rm -f -- $(printf '%q' "$transcript"); install -m 0600 /dev/null $(printf '%q' "$transcript"); printf '%s\\n' $input | /usr/bin/python3 -c $(printf '%q' "$driver") -- sudo /usr/bin/dnfast apply $(printf '%q' "$plan") >$(printf '%q' "$transcript") 2>&1; grep -F 'Continue? [y/N]' $(printf '%q' "$transcript") >/dev/null"; then
    return 1
  fi
  if [[ $answer == y ]]; then
    refresh_root_snapshot "$name"
  fi
}

assert_public_plan_rejected_as_nonroot() {
  local plan=$1
  if guest "sudo setpriv --reuid=fedora --regid=fedora --clear-groups /usr/bin/dnfast apply $(printf '%q' "$plan") --assumeyes >/tmp/dnfast-public-nonroot.log 2>&1"; then
    die 'non-root public apply unexpectedly succeeded'
  fi
  guest "grep -F 'apply requires root' /tmp/dnfast-public-nonroot.log >/dev/null"
}

assert_no_residue() {
  assert_staging_empty
  assert_input_preparation_clean
}

run_signed_install() {
  local plan
  plan=$(public_plan install dnfast-noarch signed-install)
  public_apply_yes "$plan" signed-install
  guest 'rpm -q dnfast-noarch >/dev/null'
  assert_no_residue
  record_scenario_pass signed_install
}

run_signed_remove() {
  local plan
  plan=$(public_plan remove dnfast-noarch signed-remove)
  public_apply_yes "$plan" signed-remove
  if guest 'rpm -q dnfast-noarch >/dev/null'; then die 'signed public remove left dnfast-noarch installed'; fi
  assert_no_residue
  record_scenario_pass signed_remove
}

run_public_pty_default_no() {
  local plan before
  plan=$(public_plan install dnfast-noarch public-pty-default-no)
  before=$(inventory_digest)
  public_apply_pty "$plan" n public-pty-default-no
  [[ $before == "$(inventory_digest)" ]] || die 'public PTY default-No changed installed inventory'
  if guest 'rpm -q dnfast-noarch >/dev/null'; then die 'public PTY default-No installed dnfast-noarch'; fi
  assert_no_residue
  record_scenario_pass public_pty_default_no
}

run_public_pty_yes() {
  local plan
  plan=$(public_plan install dnfast-noarch public-pty-yes)
  public_apply_pty "$plan" y public-pty-yes
  guest 'rpm -q dnfast-noarch >/dev/null'
  assert_no_residue
  record_scenario_pass public_pty_yes
}

run_signed_upgrade() {
  local install_plan upgrade_plan remove_plan
  install_plan=$(public_plan install 'dnfast-upgrade = 1.0-1' signed-upgrade-install)
  public_apply_yes "$install_plan" signed-upgrade-install
  guest "rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\\n' dnfast-upgrade | grep -Fx '1.0-1.noarch' >/dev/null"
  upgrade_plan=$(public_plan upgrade dnfast-upgrade signed-upgrade)
  public_apply_yes "$upgrade_plan" signed-upgrade
  guest "rpm -q --qf '%{VERSION}-%{RELEASE}.%{ARCH}\\n' dnfast-upgrade | grep -Fx '2.0-1.noarch' >/dev/null"
  remove_plan=$(public_plan remove dnfast-upgrade signed-upgrade-cleanup)
  public_apply_yes "$remove_plan" signed-upgrade-cleanup
  if guest 'rpm -q dnfast-upgrade >/dev/null'; then die 'signed public upgrade cleanup left dnfast-upgrade installed'; fi
  assert_no_residue
  record_scenario_pass signed_upgrade
}

run_nonroot() {
  local plan before
  plan=$(public_plan install dnfast-noarch nonroot)
  before=$(inventory_digest)
  assert_public_plan_rejected_as_nonroot "$plan"
  [[ $before == "$(inventory_digest)" ]] || die 'non-root public apply changed installed inventory'
  assert_no_residue
  record_scenario_pass nonroot
}

run_public_matrix() {
  local before_inventory before_files after_inventory after_files
  before_inventory=$(inventory_digest)
  before_files=$(managed_files_digest)
  run_signed_install
  run_signed_remove
  run_public_pty_default_no
  run_public_pty_yes
  run_signed_remove
  run_signed_upgrade
  run_nonroot
  guest 'rpmdb --verifydb'
  record_scenario_pass verifydb
  assert_no_residue
  record_scenario_pass staging_cleanup
  record_scenario_pass input_cleanup
  after_inventory=$(inventory_digest)
  after_files=$(managed_files_digest)
  [[ $before_inventory == "$after_inventory" ]] || die 'public matrix did not restore sorted package inventory'
  [[ $before_files == "$after_files" ]] || die 'public matrix did not restore managed package filesystem state'
  record_scenario_pass before_after_sorted
  guest 'rm -f /tmp/dnfast-public-inventory-digest.log /tmp/dnfast-public-managed-files-digest.log /tmp/dnfast-public-nonroot.log; rm -rf /home/fedora/dnfast-public-matrix'
}

initialize_receipt() {
  [[ -n $RECEIPT ]] || die "--receipt is required when --run is set"
  mkdir -p "$(dirname "$RECEIPT")"
  : >"$RECEIPT"
  record 'public_qemu_matrix_receipt_format=1'
  record "public_qemu_matrix_architecture=$ARCH"
  record "public_qemu_matrix_harness_sha256=$(sha256sum "$0" | awk '{print $1}')"
}

main() {
  parse_request "$@"
  validate_request
  native_kvm_preflight
  set_architecture_defaults
  if ((RUN == 0)); then
    named_scenarios
    return
  fi
  initialize_receipt
  trap finish EXIT INT TERM HUP
  boot_guest
  copy_build_inputs
  package_public_cli
  start_guest_https_fixture
  bootstrap_root_snapshot
  run_public_matrix
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi

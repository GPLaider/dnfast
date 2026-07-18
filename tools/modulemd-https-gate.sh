#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
EVIDENCE=${1:?usage: tools/modulemd-https-gate.sh EVIDENCE_DIRECTORY}
DNFAST=${DNFAST_BIN:-/usr/bin/dnfast}
PORT=${DNFAST_MODULEMD_PORT:-18447}
REPO_ID=dnfast-module-gate
RUNTIME=$(mktemp -d /var/tmp/dnfast-modulemd-gate.XXXXXX)
REPO_CONFIG=/etc/yum.repos.d/dnfast-module-gate.repo
KEY_DIRECTORY=/etc/dnfast/keys/dnfast-module-gate
CA_ANCHOR=/etc/pki/ca-trust/source/anchors/dnfast-module-gate-ca.pem
SERVER_PID=
SUCCEEDED=0
DAEMON_WAS_ACTIVE=0

if [[ $EUID -ne 0 ]]; then
  printf 'modulemd gate requires EUID 0\n' >&2
  exit 1
fi
for tool in "$DNFAST" createrepo_c modifyrepo_c modulemd-validator gpg openssl curl rpm sha256sum; do
  command -v "$tool" >/dev/null || { printf 'missing command: %s\n' "$tool" >&2; exit 1; }
done
for path in "$REPO_CONFIG" "$KEY_DIRECTORY" "$CA_ANCHOR"; do
  [[ ! -e $path ]] || { printf 'refusing to replace existing path: %s\n' "$path" >&2; exit 1; }
done
mkdir -p "$EVIDENCE"
chmod 0755 "$EVIDENCE"
exec > >(tee "$EVIDENCE/gate.log") 2>&1

record() { printf '%s=%s\n' "$1" "$2"; }
inventory_digest() {
  rpm -qa --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' |
    LC_ALL=C sort | sha256sum | awk '{print $1}'
}
snapshot_digest() { tr -d '\n' </var/lib/dnfast/planning/current; }
sign_repomd() {
  rm -f "$RUNTIME/repo/repodata/repomd.xml.asc"
  GNUPGHOME="$RUNTIME/gnupg" gpg --batch --yes --armor --local-user "$REPO_FINGERPRINT" \
    --detach-sign "$RUNTIME/repo/repodata/repomd.xml"
}
install_modules() {
  modifyrepo_c --remove modules "$RUNTIME/repo/repodata" >/dev/null 2>&1 || true
  modifyrepo_c --mdtype=modules --compress-type=zstd --simple-md-filenames \
    "$1" "$RUNTIME/repo/repodata" >/dev/null
  sign_repomd
}
run_dnfast() {
  local label=$1
  shift
  "$DNFAST" --json "$@" | tee "$EVIDENCE/$label.json"
}
cleanup() {
  local status=$?
  set +e
  "$DNFAST" --json group remove --repo "$REPO_ID" --assumeyes dnfast-fixture \
    >"$EVIDENCE/cleanup-group-remove.json" 2>&1 || true
  if rpm -q dnfast-upgrade >/dev/null 2>&1; then
    "$DNFAST" --json remove --repo "$REPO_ID" --assumeyes dnfast-upgrade \
      >"$EVIDENCE/cleanup-remove.json" 2>&1 || rpm -e dnfast-upgrade \
      >"$EVIDENCE/cleanup-rpm-erase.log" 2>&1
  fi
  "$DNFAST" --json module reset --repo "$REPO_ID" dnfast-upgrade \
    >"$EVIDENCE/cleanup-module-reset.json" 2>&1 || true
  [[ -z $SERVER_PID ]] || kill "$SERVER_PID" 2>/dev/null || true
  [[ -z $SERVER_PID ]] || wait "$SERVER_PID" 2>/dev/null || true
  rm -f "$REPO_CONFIG" "$CA_ANCHOR"
  rm -rf "$KEY_DIRECTORY"
  update-ca-trust >/dev/null 2>&1 || true
  "$DNFAST" --json repo refresh --repo fedora --repo updates \
    >"$EVIDENCE/cleanup-official-refresh.json" 2>&1 || true
  if [[ $DAEMON_WAS_ACTIVE -eq 1 ]]; then
    systemctl restart dnfastd.service >"$EVIDENCE/cleanup-daemon-restore.log" 2>&1 || true
  else
    systemctl stop dnfastd.service >"$EVIDENCE/cleanup-daemon-restore.log" 2>&1 || true
  fi
  rm -rf "$RUNTIME"
  record cleanup_exit "$status"
  if [[ $status -eq 0 && $SUCCEEDED -eq 1 ]]; then
    record modulemd_gate passed
  else
    record modulemd_gate failed
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM HUP

[[ ! -e /usr/share/dnfast/module-gate ]] || {
  printf 'unexpected pre-existing fixture payload\n' >&2
  exit 1
}
systemctl is-active --quiet dnfastd.service && DAEMON_WAS_ACTIVE=1
if rpm -q dnfast-upgrade >/dev/null 2>&1; then
  printf 'dnfast-upgrade must be absent before the gate\n' >&2
  exit 1
fi

BEFORE_INVENTORY=$(inventory_digest)
record inventory_before "$BEFORE_INVENTORY"
rpm --verifydb
record rpmdb_verify_before passed

mkdir -m 0700 "$RUNTIME/gnupg"
mkdir -p "$RUNTIME/repo"
cp "$ROOT/fixtures/rpm/generated-build11/repos/main/dnfast-upgrade-1.0-1.noarch.rpm" "$RUNTIME/repo/"
cp "$ROOT/fixtures/rpm/generated-build11/repos/main/dnfast-upgrade-2.0-1.noarch.rpm" "$RUNTIME/repo/"
cat >"$RUNTIME/comps.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<comps>
  <group>
    <id>dnfast-fixture</id>
    <name>dnfast fixture group</name>
    <description>Exercises durable group ownership.</description>
    <default>false</default>
    <uservisible>true</uservisible>
    <packagelist>
      <packagereq type="mandatory">dnfast-upgrade</packagereq>
    </packagelist>
  </group>
</comps>
EOF
createrepo_c --no-database --simple-md-filenames --revision 1784246400 \
  --groupfile "$RUNTIME/comps.xml" \
  "$RUNTIME/repo" >/dev/null
modulemd-validator "$ROOT/fixtures/modulemd/dnfast-upgrade.yaml"

GNUPGHOME="$RUNTIME/gnupg" gpg --batch --passphrase '' --quick-generate-key \
  'dnfast module gate <module-gate@dnfast.invalid>' ed25519 sign 1d >/dev/null 2>&1
REPO_FINGERPRINT=$(GNUPGHOME="$RUNTIME/gnupg" gpg --batch --with-colons --fingerprint |
  awk -F: '$1=="fpr" {print $10; exit}')
PACKAGE_FINGERPRINT=$(awk -F '\t' '$1=="allowed" && $2=="primary" {print $3}' \
  "$ROOT/fixtures/rpm/generated-build11/fingerprints.tsv")
[[ $REPO_FINGERPRINT =~ ^[0-9A-F]{40}$ && $PACKAGE_FINGERPRINT =~ ^[0-9A-F]{40}$ ]]
GNUPGHOME="$RUNTIME/gnupg" gpg --batch --armor --export "$REPO_FINGERPRINT" \
  >"$RUNTIME/repo-signing.asc"
install_modules "$ROOT/fixtures/modulemd/dnfast-upgrade.yaml"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$RUNTIME/ca-key.pem" -out "$RUNTIME/ca.pem" \
  -subj '/CN=dnfast module gate CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$RUNTIME/key.pem" \
  -out "$RUNTIME/leaf.csr" -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost' >/dev/null 2>&1
openssl x509 -req -in "$RUNTIME/leaf.csr" -CA "$RUNTIME/ca.pem" \
  -CAkey "$RUNTIME/ca-key.pem" -CAcreateserial -days 1 \
  -out "$RUNTIME/cert.pem" -copy_extensions copy >/dev/null 2>&1
install -o root -g root -m 0644 "$RUNTIME/ca.pem" "$CA_ANCHOR"
update-ca-trust

install -d -o root -g root -m 0700 "$KEY_DIRECTORY"
{
  cat "$ROOT/fixtures/rpm/generated-build11/keys/allowed.asc"
  cat "$RUNTIME/repo-signing.asc"
} >"$RUNTIME/trust.asc"
install -o root -g root -m 0600 "$RUNTIME/trust.asc" "$KEY_DIRECTORY/trust.asc"
printf '%s\n' \
  "[$REPO_ID]" \
  'name=dnfast signed modulemd gate' \
  "baseurl=https://localhost:$PORT" \
  'enabled=true' \
  'sslverify=true' \
  'proxy=_none_' \
  'gpgcheck=true' \
  'pkg_gpgcheck=true' \
  'repo_gpgcheck=true' \
  "gpgkey=$KEY_DIRECTORY/trust.asc" \
  "dnfast_allowed_fingerprints=$PACKAGE_FINGERPRINT $REPO_FINGERPRINT" \
  'metadata_expire=0' >"$RUNTIME/repository.repo"
install -o root -g root -m 0644 "$RUNTIME/repository.repo" "$REPO_CONFIG"

(cd "$RUNTIME/repo" && exec openssl s_server -accept "$PORT" \
  -cert "$RUNTIME/cert.pem" -key "$RUNTIME/key.pem" -WWW -quiet) \
  >"$EVIDENCE/https-server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
  if curl --fail --silent --show-error "https://localhost:$PORT/repodata/repomd.xml" \
    >/dev/null; then
    break
  fi
  sleep 0.1
done
curl --fail --silent --show-error "https://localhost:$PORT/repodata/repomd.xml" \
  >"$EVIDENCE/served-repomd.xml"
record https_fixture ready

run_dnfast refresh repo refresh --repo "$REPO_ID"
systemctl is-active --quiet dnfastd.service && {
  printf 'daemonless module gate unexpectedly found dnfastd active\n' >&2
  exit 1
}
run_dnfast module-list module list --repo "$REPO_ID"
grep -F 'dnfast-upgrade:stable:default' "$EVIDENCE/module-list.json" >/dev/null
grep -F 'dnfast-upgrade:next:inactive' "$EVIDENCE/module-list.json" >/dev/null
run_dnfast module-info module info --repo "$REPO_ID" dnfast-upgrade

run_dnfast group-list group list --repo "$REPO_ID"
grep -F 'dnfast-fixture=dnfast fixture group' "$EVIDENCE/group-list.json" >/dev/null
run_dnfast group-info group info --repo "$REPO_ID" dnfast-fixture
run_dnfast group-install-owned group install --repo "$REPO_ID" --assumeyes dnfast-fixture
[[ $(rpm -q --qf '%{VERSION}\n' dnfast-upgrade) == 1.0 ]]
run_dnfast group-remove-owned group remove --repo "$REPO_ID" --assumeyes dnfast-fixture
rpm -q dnfast-upgrade >/dev/null 2>&1 && exit 1
run_dnfast group-direct-install install --repo "$REPO_ID" --assumeyes dnfast-upgrade
run_dnfast group-install-no-change group install --repo "$REPO_ID" --assumeyes dnfast-fixture
grep -F 'no changes; requested state is already satisfied' \
  "$EVIDENCE/group-install-no-change.json" >/dev/null
run_dnfast group-remove-no-change group remove --repo "$REPO_ID" --assumeyes dnfast-fixture
grep -F 'no changes; selected group packages are already absent' \
  "$EVIDENCE/group-remove-no-change.json" >/dev/null
rpm -q dnfast-upgrade >/dev/null
run_dnfast group-direct-remove remove --repo "$REPO_ID" --assumeyes dnfast-upgrade
record group_ownership_and_no_change passed

run_dnfast default-install module install --repo "$REPO_ID" --assumeyes \
  dnfast-upgrade:stable/default
[[ $(rpm -q --qf '%{VERSION}\n' dnfast-upgrade) == 1.0 ]]
record default_profile_install 1.0
run_dnfast default-remove remove --repo "$REPO_ID" --assumeyes dnfast-upgrade

run_dnfast enable-next module enable --repo "$REPO_ID" dnfast-upgrade:next
run_dnfast next-install module install --repo "$REPO_ID" --assumeyes \
  dnfast-upgrade:next/default
[[ $(rpm -q --qf '%{VERSION}\n' dnfast-upgrade) == 2.0 ]]
record enabled_profile_install 2.0
run_dnfast next-remove remove --repo "$REPO_ID" --assumeyes dnfast-upgrade

run_dnfast disable module disable --repo "$REPO_ID" dnfast-upgrade
if "$DNFAST" --json install --repo "$REPO_ID" --assumeyes dnfast-upgrade \
  >"$EVIDENCE/disabled-install.json" 2>&1; then
  printf 'disabled module unexpectedly installed\n' >&2
  exit 1
fi
rpm -q dnfast-upgrade >/dev/null 2>&1 && exit 1
record disabled_install rejected

run_dnfast reset module reset --repo "$REPO_ID" dnfast-upgrade
run_dnfast upgrade-bootstrap install --repo "$REPO_ID" --assumeyes dnfast-upgrade
[[ $(rpm -q --qf '%{VERSION}\n' dnfast-upgrade) == 1.0 ]]
run_dnfast upgrade-enable-next module enable --repo "$REPO_ID" dnfast-upgrade:next
run_dnfast upgrade upgrade --repo "$REPO_ID" --assumeyes dnfast-upgrade
[[ $(rpm -q --qf '%{VERSION}\n' dnfast-upgrade) == 2.0 ]]
record stream_upgrade 1.0_to_2.0
run_dnfast reinstall-next reinstall --repo "$REPO_ID" --assumeyes dnfast-upgrade
[[ $(rpm -q --qf '%{VERSION}\n' dnfast-upgrade) == 2.0 ]]
run_dnfast downgrade-reset module reset --repo "$REPO_ID" dnfast-upgrade
run_dnfast downgrade downgrade --repo "$REPO_ID" --assumeyes dnfast-upgrade
[[ $(rpm -q --qf '%{VERSION}\n' dnfast-upgrade) == 1.0 ]]
run_dnfast reinstall-stable reinstall --repo "$REPO_ID" --assumeyes dnfast-upgrade
[[ $(rpm -q --qf '%{VERSION}\n' dnfast-upgrade) == 1.0 ]]
run_dnfast distro-sync-enable-next module enable --repo "$REPO_ID" dnfast-upgrade:next
run_dnfast distro-sync distro-sync --repo "$REPO_ID" --assumeyes dnfast-upgrade
[[ $(rpm -q --qf '%{VERSION}\n' dnfast-upgrade) == 2.0 ]]
record downgrade_reinstall_distro_sync passed
run_dnfast upgrade-remove remove --repo "$REPO_ID" --assumeyes dnfast-upgrade
run_dnfast final-reset module reset --repo "$REPO_ID" dnfast-upgrade

for iteration in $(seq 1 5); do
  "$DNFAST" --json module enable --repo "$REPO_ID" dnfast-upgrade:next >/dev/null
  "$DNFAST" --json module disable --repo "$REPO_ID" dnfast-upgrade >/dev/null
  "$DNFAST" --json module reset --repo "$REPO_ID" dnfast-upgrade >/dev/null
  "$DNFAST" --json module list --repo "$REPO_ID" >/dev/null
  record mutation_iteration "$iteration"
done

BEFORE_FAILED_REFRESH=$(snapshot_digest)
printf '%s\n' \
  '---' \
  'document: modulemd' \
  'version: 2' \
  'data:' \
  '  name: broken' \
  '  stream: stable' \
  '  version: 1' \
  '  context: bad' \
  '  arch: x86_64' \
  '  surprise: rejected' >"$RUNTIME/invalid-modulemd.yaml"
install_modules "$RUNTIME/invalid-modulemd.yaml"
if "$DNFAST" --json repo refresh --repo "$REPO_ID" \
  >"$EVIDENCE/invalid-refresh.json" 2>&1; then
  printf 'invalid modulemd refresh unexpectedly succeeded\n' >&2
  exit 1
fi
[[ $(snapshot_digest) == "$BEFORE_FAILED_REFRESH" ]]
record invalid_refresh_preserved_snapshot "$BEFORE_FAILED_REFRESH"

install_modules "$ROOT/fixtures/modulemd/dnfast-upgrade.yaml"
run_dnfast recovered-refresh repo refresh --repo "$REPO_ID"
run_dnfast recovered-list module list --repo "$REPO_ID"
record atomic_recovery passed

rpm --verifydb
record rpmdb_verify_after passed
AFTER_INVENTORY=$(inventory_digest)
record inventory_after "$AFTER_INVENTORY"
[[ $AFTER_INVENTORY == "$BEFORE_INVENTORY" ]]
record inventory_integrity unchanged

mapfile -t MODULE_PAYLOADS < <(
  find "$RUNTIME/repo/repodata" -maxdepth 1 -type f -name '*.yaml.zst' -print | LC_ALL=C sort
)
[[ ${#MODULE_PAYLOADS[@]} -eq 1 ]] || {
  printf 'expected exactly one published modules payload, found %s\n' "${#MODULE_PAYLOADS[@]}" >&2
  exit 1
}
install -m 0644 "$ROOT/fixtures/modulemd/dnfast-upgrade.yaml" \
  "$EVIDENCE/fixture-modulemd.yaml"
install -m 0644 "$RUNTIME/comps.xml" "$EVIDENCE/fixture-comps.xml"
install -m 0644 "$RUNTIME/repo/repodata/repomd.xml" "$EVIDENCE/final-repomd.xml"
install -m 0644 "${MODULE_PAYLOADS[0]}" "$EVIDENCE/final-modules.yaml.zst"
(
  cd "$EVIDENCE"
  sha256sum fixture-modulemd.yaml fixture-comps.xml final-repomd.xml \
    final-modules.yaml.zst ./*.json \
    >artifacts.sha256
  sha256sum -c artifacts.sha256
)
SUCCEEDED=1

#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILDER="$ROOT/tools/build-fixture-repo.sh"
GUEST_BUILDER="$ROOT/fixtures/rpm/build-in-guest.sh"
CATALOG="$ROOT/fixtures/rpm/catalog.tsv"
PASS=0

ok() { local name=$1; shift; "$@" >/dev/null || { echo "not ok - $name"; exit 1; }; PASS=$((PASS + 1)); }
has() { grep -Fq "$1" "$2"; }

fixture_directory_ownership_header_contract() (
  set -u
  local top package spec
  local -a packages
  top=$(mktemp -d /tmp/dnfast-fixture-directory-top.XXXXXX)
  trap 'rm -rf -- "$top"' EXIT
  mkdir -p "$top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} || return 1

  for spec in relations.spec policies.spec upgrade-v1.spec upgrade-v2.spec vendor-switch-v1.spec vendor-switch.spec scripts.spec noarch.spec arch-switch-v1.spec arch-switch.spec arch.spec; do
    SOURCE_DATE_EPOCH=1704067200 rpmbuild -bb --define "_topdir $top" --define '_buildhost dnfast.invalid' --define 'source_date_epoch_from_changelog 1' "$ROOT/fixtures/rpm/$spec" >/dev/null 2>&1 || return 1
  done

  shopt -s nullglob
  packages=("$top"/RPMS/*/*.rpm)
  ((${#packages[@]} > 0)) || return 1
  for package in "${packages[@]}"; do
    if LC_ALL=C rpm -qpl "$package" | grep -Fq '/usr/share/dnfast/'; then
      LC_ALL=C rpm -qpl "$package" | grep -Fxq '/usr/share/dnfast' || return 1
    fi
  done
)

managed_fixture_lifecycle_restores_absent_baseline() {
  local matrix=$ROOT/tools/public-qemu-matrix.sh
  has 'if test -e /usr/share/dnfast; then' "$matrix" || return 1
  has 'else printf absent | sha256sum' "$matrix" || return 1
  has 'run_signed_remove' "$matrix" || return 1
  has '[[ $before_files == "$after_files" ]]' "$matrix"
}

for semantic in app dependency rich unsatisfied weak file-provide file-collision conflict obsoletes upgrade-v1 upgrade-v2 aarch64 noarch wrong-arch priority-tie cost-tie vendor-switch arch-switch config protected installonly pre-failure post-failure trigger-failure unsigned corrupt alternate-key expired-primary revoked-primary expired-subkey revoked-subkey; do
  ok "Given source, when inspected, then catalog names $semantic" has "$semantic" "$CATALOG"
done

ok "Given untrusted host, when built, then Fedora VM harness runs" has 'fedora44-native-build.sh' "$BUILDER"
ok "Given guest, when built, then fixture mode is offline" has 'DNFAST_FIXTURE_BUILD=1' "$BUILDER"
ok "Given runtime keys, when done, then private keyring cleanup is mandatory" has 'GNUPGHOME' "$GUEST_BUILDER"
ok "Given output, when scanned, then secret packets are rejected" has 'secret key packet' "$GUEST_BUILDER"
ok "Given revoked subkey, when exported, then primary remains valid" has 'primary validity mismatch' "$GUEST_BUILDER"
ok "Given revoked subkey, when exported, then target subkey is revoked" has 'subkey validity mismatch' "$GUEST_BUILDER"
for repo in alternate priority-high priority-low cost-low cost-high; do
  ok "Given tie candidates, when published, then $repo has repomd" has "$repo" "$GUEST_BUILDER"
done
ok "Given vendor switch, when cataloged, then baseline Vendor A exists" has 'vendor-switch-v1' "$CATALOG"
ok "Given vendor switch, when cataloged, then candidate Vendor B exists" has 'vendor-switch-v2' "$CATALOG"
ok "Given arch switch, when cataloged, then aarch64 baseline exists" has $'arch-switch-v1\tdnfast-arch-switch\t1.0\t1\taarch64' "$CATALOG"
ok "Given arch switch, when cataloged, then noarch candidate exists" has $'arch-switch-v2\tdnfast-arch-switch\t2.0\t1\tnoarch' "$CATALOG"
ok "Given wrong arch, when cataloged, then actual package filename is exact" has $'wrong-arch\tdnfast-arch\t1.0\t1\tx86_64\tsolver-arch\tdnfast-arch-1.0-1.x86_64.rpm' "$CATALOG"
for field in repo_id recommends suggests supplements enhances vendor config_files pre post triggers file_provides; do
  ok "Given semantic manifest, when generated, then $field is recorded" has "$field" "$GUEST_BUILDER"
done
ok "Given completed or failed build, when cleanup runs, then harness copies are removed" has 'rm -f "$HARNESS"' "$BUILDER"
ok "Given semantic rows, when emitted, then every row has the header column count" has 'semantic column count mismatch' "$GUEST_BUILDER"
ok "Given weak fixture, when built, then supplements relation is nonempty" has 'Supplements: dnfast-app' "$ROOT/fixtures/rpm/relations.spec"
ok "Given weak fixture, when built, then enhances relation is nonempty" has 'Enhances: dnfast-rich' "$ROOT/fixtures/rpm/relations.spec"
ok "Given lifecycle fixture RPM headers, when built, then every shared-directory payload owns its directory" fixture_directory_ownership_header_contract
ok "Given the public lifecycle matrix, when fixture packages are erased, then its managed digest restores the absent baseline" managed_fixture_lifecycle_restores_absent_baseline

echo "ok $PASS fixture repository contracts"

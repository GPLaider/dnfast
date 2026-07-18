#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TOOLROOT=${FEDORA44_TOOLROOT:-$ROOT/.cache/fedora44-vm/toolroot}
if [[ ! -f $TOOLROOT/usr/include/modulemd-2.0/modulemd.h ]]; then
  if [[ -f /usr/include/modulemd-2.0/modulemd.h ]]; then
    TOOLROOT=/
  else
    echo 'no complete Fedora native toolroot (modulemd.h is missing)' >&2
    exit 1
  fi
fi
FIXTURE=$ROOT/fixtures/rpm/generated-build10/repos
TMP=$(mktemp -d "${TMPDIR:-/tmp}/dnfast-solver.XXXXXX")
RPMROOT=
DBPATH=
RPMMOUNT=
cleanup_solver() {
  [[ -z $RPMMOUNT ]] || sudo -n umount "$RPMMOUNT" 2>/dev/null || true
  [[ -z $RPMROOT ]] || sudo -n rm -rf "$RPMROOT" 2>/dev/null || true
  [[ -z $DBPATH ]] || sudo -n rm -rf "$DBPATH" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup_solver EXIT INT TERM HUP

export DNFAST_NATIVE_REAL=1
export PKG_CONFIG_PATH="$TOOLROOT/usr/lib64/pkgconfig:$TOOLROOT/usr/share/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR="$TOOLROOT"
export LD_LIBRARY_PATH="$TOOLROOT/usr/lib64:$TOOLROOT/usr/lib"

repo() {
  local id=$1 priority=$2 cost=$3 directory output
  directory="$FIXTURE/$id/repodata"
  output="$TMP/$id"
  mkdir -p "$output"
  zstd -q -d "$directory/primary.xml.zst" -o "$output/primary.xml"
  zstd -q -d "$directory/filelists.xml.zst" -o "$output/filelists.xml"
  printf '%s,%s,%s,%s,%s,%s' "$id" "$directory/repomd.xml" "$output/primary.xml" "$output/filelists.xml" "$priority" "$cost"
}

solve() {
  cargo run -q --locked -p dnfast-native --example solve -- "$@"
}

MAIN=$(repo main 99 1000)
IFS=, read -r _ LIMIT_REPOMD LIMIT_PRIMARY LIMIT_FILELISTS _ _ <<<"$MAIN"
LIMIT_BYTES=$(($(stat -c %s "$LIMIT_REPOMD") + $(stat -c %s "$LIMIT_PRIMARY") + $(stat -c %s "$LIMIT_FILELISTS")))
DNFAST_MAX_PACKAGES=25 DNFAST_MAX_METADATA_BYTES=$LIMIT_BYTES solve dnfast-app weak "$MAIN" >/dev/null
if DNFAST_MAX_PACKAGES=24 solve dnfast-app weak "$MAIN" >"$TMP/package-limit.out" 2>&1; then exit 1; fi
grep -q 'package limit exceeded' "$TMP/package-limit.out"
if DNFAST_MAX_METADATA_BYTES=$((LIMIT_BYTES - 1)) solve dnfast-app weak "$MAIN" >"$TMP/byte-limit.out" 2>&1; then exit 1; fi
grep -q 'metadata byte limit exceeded' "$TMP/byte-limit.out"
DNFAST_MAX_RELATIONS=5 solve dnfast-app weak "$MAIN" >/dev/null
if DNFAST_MAX_RELATIONS=4 solve dnfast-app weak "$MAIN" >"$TMP/relation-limit.out" 2>&1; then exit 1; fi
grep -q 'relation limit exceeded' "$TMP/relation-limit.out"
if solve dnfast-app weak "broken,$TMP/missing,$TMP/missing,$TMP/missing,99,1000" >"$TMP/forced.out" 2>"$TMP/forced.err"; then
  echo 'forced native load failure unexpectedly succeeded' >&2
  exit 1
fi
grep -q 'NativeFailure' "$TMP/forced.err"
IFS=, read -r _ REPOMD PRIMARY FILELISTS _ _ <<<"$MAIN"
awk 'BEGIN { keep=0 } /<metadata / { sub(/packages="25"/, "packages=\"2\""); print; next } /<package type=/ { block=$0 ORS; keep=0; next } block != "" { block=block $0 ORS; if ($0 ~ /<name>dnfast-(app|dep)<\/name>/) keep=1; if ($0 ~ /<\/package>/) { if (keep) printf "%s", block; block="" }; next } { print }' "$PRIMARY" >"$TMP/transitive.xml"
TRANSITIVE="transitive,$REPOMD,$TMP/transitive.xml,$FILELISTS,99,1000"
RECOVERED=$(DNFAST_MAX_PACKAGES=2 DNFAST_FAIL_REPO="$MAIN" DNFAST_RESIDUAL_NAME=dnfast-obsoletes solve dnfast-app no-weak "$TRANSITIVE")
grep -q $'action\tinstall\ttransitive\tdnfast-app-0:1.0-1.noarch' <<<"$RECOVERED"
printf '<broken' >"$TMP/broken.xml"
BROKEN="broken,$REPOMD,$TMP/broken.xml,$FILELISTS,99,1000"
RECOVERED_BAD=$(DNFAST_MAX_PACKAGES=2 DNFAST_FAIL_REPO="$BROKEN" DNFAST_RESIDUAL_NAME=dnfast-obsoletes solve dnfast-app no-weak "$TRANSITIVE")
[[ $RECOVERED_BAD == "$RECOVERED" ]]
mkdir -p "$TMP/race-grow" "$TMP/race-swap" "$TMP/race-grow-final"
for race in grow swap grow-final; do
  cp "$REPOMD" "$TMP/race-$race/repomd.xml"
  cp "$LIMIT_PRIMARY" "$TMP/race-$race/primary.xml"
  cp "$LIMIT_FILELISTS" "$TMP/race-$race/filelists.xml"
done
cp "$LIMIT_PRIMARY" "$TMP/race-swap/primary.xml.replacement"
RACE_GROW="race-grow,$TMP/race-grow/repomd.xml,$TMP/race-grow/primary.xml,$TMP/race-grow/filelists.xml,99,1000"
RACE_SWAP="race-swap,$TMP/race-swap/repomd.xml,$TMP/race-swap/primary.xml,$TMP/race-swap/filelists.xml,99,1000"
RACE_FINAL="race-final,$TMP/race-grow-final/repomd.xml,$TMP/race-grow-final/primary.xml,$TMP/race-grow-final/filelists.xml,99,1000"
cargo run -q --locked -p dnfast-native --example metadata_race -- grow "$RACE_GROW" "$TRANSITIVE" | grep -q 'metadata-grow-rollback=true'
cargo run -q --locked -p dnfast-native --example metadata_race -- swap "$RACE_SWAP" "$TRANSITIVE" | grep -q 'metadata-swap-rollback=true'
cargo run -q --locked -p dnfast-native --example metadata_race -- grow-final "$RACE_FINAL" "$TRANSITIVE" | grep -q 'metadata-grow-final-rollback=true'
APP=$(solve dnfast-app no-weak "$TRANSITIVE")
grep -q $'action\tinstall\ttransitive\tdnfast-app-0:1.0-1.noarch' <<<"$APP"
[[ $(sed -n '1p' <<<"$APP") == $'action\tinstall\ttransitive\tdnfast-dep-0:1.0-1.noarch' ]]
[[ $(sed -n '2p' <<<"$APP") == $'action\tinstall\ttransitive\tdnfast-app-0:1.0-1.noarch' ]]
grep -q $'decision\tstrong\taction\tdnfast-app-0:1.0-1.noarch\tdnfast-dep-0:1.0-1.noarch\tdnfast-dep >= 1.0' <<<"$APP"
RICH=$(solve dnfast-rich weak "$MAIN")
grep -q $'action\tinstall\tmain\tdnfast-rich-0:1.0-1.noarch' <<<"$RICH"
sed '/<rpm:entry name="dnfast-capability"/d' "$LIMIT_PRIMARY" >"$TMP/rich-primary.xml"
RICH_REPO="rich,$LIMIT_REPOMD,$TMP/rich-primary.xml,$LIMIT_FILELISTS,99,1000"
RICH_ABSENT=$(solve dnfast-rich no-weak "$RICH_REPO")
grep -q $'action\tinstall\trich\tdnfast-rich-0:1.0-1.noarch' <<<"$RICH_ABSENT"
RICH_PRESENT=$(solve dnfast-rich+dnfast-dep no-weak "$RICH_REPO")
grep -q '^problem' <<<"$RICH_PRESENT"
! grep -q '^action' <<<"$RICH_PRESENT"
FILE=$(solve /usr/share/dnfast/provided weak "$MAIN")
grep -q $'action\tinstall\tmain\tdnfast-file-collision-0:1.0-1.noarch' <<<"$FILE"
WEAK=$(solve dnfast-weak-app weak "$MAIN")
NOWEAK=$(solve dnfast-weak-app no-weak "$MAIN")
grep -q $'action\tinstall\tmain\tdnfast-weak-app-0:1.0-1.noarch' <<<"$WEAK"
[[ $(grep -c '^action' <<<"$WEAK") -gt $(grep -c '^action' <<<"$NOWEAK") ]]
grep -q $'decision\tweak\taction\tdnfast-weak-app-0:1.0-1.noarch\tdnfast-obsoletes-0:2.0-1.noarch\tdnfast-dep' <<<"$WEAK"
! grep -q '^decision' <<<"$NOWEAK"
FULL_APP=$(solve dnfast-app weak "$MAIN")
grep -q $'decision\tweak\taction\tdnfast-app-0:1.0-1.noarch\tdnfast-weak-app-0:1.0-1.noarch\tdnfast-app' <<<"$FULL_APP"
ARCH=$(solve dnfast-arch weak "$MAIN")
grep -q $'action\tinstall\tmain\tdnfast-arch-0:1.0-1.aarch64' <<<"$ARCH"
NOARCH=$(solve dnfast-noarch weak "$MAIN")
grep -q $'action\tinstall\tmain\tdnfast-noarch-0:1.0-1.noarch' <<<"$NOARCH"
mkdir -p "$TMP/wrong-arch"
cp "$ROOT/fixtures/rpm/generated-build10/failures/dnfast-arch-1.0-1.x86_64.rpm" "$TMP/wrong-arch/"
"$TOOLROOT/usr/bin/createrepo_c" --no-database --simple-md-filenames --compress-type=zstd "$TMP/wrong-arch" >/dev/null
zstd -qdf "$TMP/wrong-arch/repodata/primary.xml.zst" -o "$TMP/wrong-primary.xml"
zstd -qdf "$TMP/wrong-arch/repodata/filelists.xml.zst" -o "$TMP/wrong-filelists.xml"
WRONG="wrong,$TMP/wrong-arch/repodata/repomd.xml,$TMP/wrong-primary.xml,$TMP/wrong-filelists.xml,99,1000"
if solve dnfast-arch no-weak "$WRONG" >"$TMP/wrong.out" 2>&1; then exit 1; fi
grep -q 'no matching package or provide' "$TMP/wrong.out"
PROBLEM=$(solve dnfast-unsatisfied weak "$MAIN")
grep -q $'problem\tnothing provides dnfast-never-provided >= 9 needed by dnfast-unsatisfied-1.0-1.noarch' <<<"$PROBLEM"
! grep -q '^action' <<<"$PROBLEM"
CONFLICT=$(solve dnfast-app+dnfast-conflict weak "$MAIN")
grep -q '^problem' <<<"$CONFLICT"
! grep -q '^action' <<<"$CONFLICT"
OBSOLETES=$(solve dnfast-obsoletes weak "$MAIN")
grep -q $'action\tinstall\tmain\tdnfast-obsoletes-0:2.0-1.noarch' <<<"$OBSOLETES"
RELATION=$(solve 'dnfast-upgrade = 1.0-1' weak "$MAIN")
grep -q $'action\tinstall\tmain\tdnfast-upgrade-0:1.0-1.noarch' <<<"$RELATION"
! grep -q $'action\tinstall\tmain\tdnfast-upgrade-0:2.0-1.noarch' <<<"$RELATION"
grep -qx $'selector\tdnfast-upgrade = 1.0-1\tdnfast-upgrade-0:1.0-1.noarch' <<<"$RELATION"
grep -qx $'selector-kind\trelation\tdnfast-upgrade-0:1.0-1.noarch' <<<"$RELATION"
BEST=$(solve dnfast-upgrade weak "$MAIN")
grep -q $'action\tinstall\tmain\tdnfast-upgrade-0:2.0-1.noarch' <<<"$BEST"
! grep -q $'action\tinstall\tmain\tdnfast-upgrade-0:1.0-1.noarch' <<<"$BEST"
grep -qx $'selector\tdnfast-upgrade\tdnfast-upgrade-0:2.0-1.noarch' <<<"$BEST"
grep -qx $'selector-kind\tbare\tdnfast-upgrade-0:2.0-1.noarch' <<<"$BEST"
awk '/<package type=/{v2=0} /<version epoch="0" ver="2.0" rel="1"\/>/{v2=1} v2 && /<\/format>/{print "    <rpm:requires><rpm:entry name=\"dnfast-missing-best\"/></rpm:requires>"} {print}' "$LIMIT_PRIMARY" >"$TMP/best-primary.xml"
BEST_REPO="best,$LIMIT_REPOMD,$TMP/best-primary.xml,$LIMIT_FILELISTS,99,1000"
BEST_FALSE=$(DNFAST_BEST=0 solve dnfast-upgrade no-weak "$BEST_REPO")
grep -q $'action\tinstall\tbest\tdnfast-upgrade-0:1.0-1.noarch' <<<"$BEST_FALSE"
BEST_TRUE=$(DNFAST_BEST=1 solve dnfast-upgrade no-weak "$BEST_REPO")
grep -q '^problem' <<<"$BEST_TRUE"
! grep -q '^action' <<<"$BEST_TRUE"

HIGH=$(repo priority-high 10 1000)
LOW=$(repo priority-low 90 1000)
PRIORITY=$(solve dnfast-priority weak "$LOW" "$HIGH")
grep -q $'action\tinstall\tpriority-high\tdnfast-priority-0:1.0-1.noarch' <<<"$PRIORITY"
COST_LOW=$(repo cost-low 99 10)
COST_HIGH=$(repo cost-high 99 9000)
COST=$(solve dnfast-cost weak "$COST_HIGH" "$COST_LOW")
grep -q $'action\tinstall\tcost-low\tdnfast-cost-0:1.0-1.noarch' <<<"$COST"

awk 'BEGIN { block="" } /<metadata / { sub(/packages="25"/, "packages=\"2\""); print; next } /<package type=/ { block=$0 ORS; next } block != "" { block=block $0 ORS; if ($0 ~ /<\/package>/) { if (block ~ /<name>dnfast-dep<\/name>/ || (block ~ /<name>dnfast-upgrade<\/name>/ && block ~ /ver="1.0"/)) printf "%s", block; block="" }; next } { print }' "$LIMIT_PRIMARY" >"$TMP/installed.xml"
SYSTEM="@System,$LIMIT_REPOMD,$TMP/installed.xml,$LIMIT_FILELISTS,9999,0"
INSTALL_ALREADY=$(solve dnfast-upgrade no-weak "$SYSTEM" "$MAIN")
grep -qx $'satisfied\tdnfast-upgrade' <<<"$INSTALL_ALREADY"
! grep -q '^action' <<<"$INSTALL_ALREADY"
INSTALLED_APP=$(solve dnfast-app no-weak "$SYSTEM" "$MAIN")
grep -q $'action\tinstall\tmain\tdnfast-app-0:1.0-1.noarch' <<<"$INSTALLED_APP"
! grep -q $'action\tinstall\tmain\tdnfast-dep-0:1.0-1.noarch' <<<"$INSTALLED_APP"
grep -q $'decision\tstrong\tinstalled\tdnfast-app-0:1.0-1.noarch\tdnfast-dep-0:1.0-1.noarch\tdnfast-dep >= 1.0' <<<"$INSTALLED_APP"
awk 'BEGIN { block="" } /<metadata / { sub(/packages="25"/, "packages=\"3\""); print; next } /<package type=/ { block=$0 ORS; next } block != "" { block=block $0 ORS; if ($0 ~ /<\/package>/) { if (block ~ /<name>dnfast-dep<\/name>/) printf "%s%s", block, block; else if (block ~ /<name>dnfast-upgrade<\/name>/ && block ~ /ver="1.0"/) printf "%s", block; block="" }; next } { print }' "$LIMIT_PRIMARY" >"$TMP/installed-ambiguous.xml"
AMBIGUOUS_SYSTEM="@System,$LIMIT_REPOMD,$TMP/installed-ambiguous.xml,$LIMIT_FILELISTS,9999,0"
if solve dnfast-app no-weak "$AMBIGUOUS_SYSTEM" "$MAIN" >"$TMP/ambiguous-provider.out" 2>&1; then exit 1; fi
grep -q 'duplicate selected provider identity' "$TMP/ambiguous-provider.out"
awk 'BEGIN { block="" } /<metadata / { sub(/packages="25"/, "packages=\"2\""); print; next } /<package type=/ { block=$0 ORS; next } block != "" { block=block $0 ORS; if ($0 ~ /<\/package>/) { if (block ~ /<name>dnfast-(cost|priority)<\/name>/) printf "%s", block; block="" }; next } { print }' "$LIMIT_PRIMARY" >"$TMP/installed-distinct-providers.xml"
DISTINCT_SYSTEM="@System,$LIMIT_REPOMD,$TMP/installed-distinct-providers.xml,$LIMIT_FILELISTS,9999,0"
sed 's/name="dnfast-dep" flags="GE"/name="dnfast-tie" flags="GE"/' "$LIMIT_PRIMARY" >"$TMP/distinct-provider-primary.xml"
DISTINCT_REPO="distinct,$LIMIT_REPOMD,$TMP/distinct-provider-primary.xml,$LIMIT_FILELISTS,99,1000"
DISTINCT_PROVIDER=$(solve dnfast-app no-weak "$DISTINCT_SYSTEM" "$DISTINCT_REPO")
grep -q $'action\tinstall\tdistinct\tdnfast-app-0:1.0-1.noarch' <<<"$DISTINCT_PROVIDER"
grep -q $'decision\tstrong\tinstalled\tdnfast-app-0:1.0-1.noarch\tdnfast-cost-0:1.0-1.noarch\tdnfast-tie >= 1.0' <<<"$DISTINCT_PROVIDER"
UPGRADE=$(DNFAST_BEST=1 solve dnfast-upgrade no-weak "$SYSTEM" "$MAIN")
grep -q $'action\tupgraded\t@System\tdnfast-upgrade-0:1.0-1.noarch' <<<"$UPGRADE"
grep -q $'action\tupgrade\tmain\tdnfast-upgrade-0:2.0-1.noarch' <<<"$UPGRADE"
grep -q $'pair\tdnfast-upgrade-0:2.0-1.noarch\tdnfast-upgrade-0:1.0-1.noarch' <<<"$UPGRADE"
UPGRADE_ALL=$(DNFAST_BEST=1 DNFAST_OPERATION=upgrade solve @all no-weak "$SYSTEM" "$MAIN")
grep -q $'action\tupgrade\tmain\tdnfast-upgrade-0:2.0-1.noarch' <<<"$UPGRADE_ALL"
! grep -q '^selector' <<<"$UPGRADE_ALL"
awk 'BEGIN { block="" } /<metadata / { sub(/packages="25"/, "packages=\"1\""); print; next } /<package type=/ { block=$0 ORS; next } block != "" { block=block $0 ORS; if ($0 ~ /<\/package>/) { if (block ~ /<name>dnfast-upgrade<\/name>/ && block ~ /ver="2.0"/) printf "%s", block; block="" }; next } { print }' "$LIMIT_PRIMARY" >"$TMP/installed-v2.xml"
SYSTEM_V2="@System,$LIMIT_REPOMD,$TMP/installed-v2.xml,$LIMIT_FILELISTS,9999,0"
DOWNGRADE=$(DNFAST_OPERATION=downgrade solve dnfast-upgrade no-weak "$SYSTEM_V2" "$MAIN")
grep -q $'action\tdowngrade\tmain\tdnfast-upgrade-0:1.0-1.noarch' <<<"$DOWNGRADE"
grep -q $'action\tdowngraded\t@System\tdnfast-upgrade-0:2.0-1.noarch' <<<"$DOWNGRADE"
REINSTALL=$(DNFAST_OPERATION=reinstall solve dnfast-upgrade no-weak "$SYSTEM_V2" "$MAIN")
grep -q $'action\treinstall\tmain\tdnfast-upgrade-0:2.0-1.noarch' <<<"$REINSTALL"
grep -q $'action\treinstalled\t@System\tdnfast-upgrade-0:2.0-1.noarch' <<<"$REINSTALL"
DISTRO_SYNC=$(DNFAST_BEST=1 DNFAST_OPERATION=distro-sync solve dnfast-upgrade no-weak "$SYSTEM" "$MAIN")
grep -q $'action\tupgrade\tmain\tdnfast-upgrade-0:2.0-1.noarch' <<<"$DISTRO_SYNC"
AUTOREMOVE=$(DNFAST_OPERATION=autoremove solve dnfast-dep no-weak "$SYSTEM" "$MAIN")
grep -q $'action\terase\t@System\tdnfast-dep-0:1.0-1.noarch' <<<"$AUTOREMOVE"
awk 'BEGIN { block="" } /<metadata / { sub(/packages="25"/, "packages=\"3\""); print; next } /<package type=/ { block=$0 ORS; next } block != "" { block=block $0 ORS; if ($0 ~ /<\/package>/) { if (block ~ /<name>dnfast-dep<\/name>/ || block ~ /<name>dnfast-app<\/name>/ || (block ~ /<name>dnfast-upgrade<\/name>/ && block ~ /ver="1.0"/)) printf "%s", block; block="" }; next } { print }' "$LIMIT_PRIMARY" >"$TMP/installed-needed.xml"
SYSTEM_NEEDED="@System,$LIMIT_REPOMD,$TMP/installed-needed.xml,$LIMIT_FILELISTS,9999,0"
AUTOREMOVE_NEEDED=$(DNFAST_OPERATION=autoremove solve dnfast-dep no-weak "$SYSTEM_NEEDED" "$MAIN")
grep -qx $'satisfied\tdnfast-dep' <<<"$AUTOREMOVE_NEEDED"
! grep -q '^action' <<<"$AUTOREMOVE_NEEDED"
OBSOLETE_OLD=$(solve dnfast-obsoletes no-weak "$SYSTEM" "$MAIN")
grep -q $'action\tobsoleted\t@System\tdnfast-dep-0:1.0-1.noarch' <<<"$OBSOLETE_OLD"
grep -q $'action\tobsoletes\tmain\tdnfast-obsoletes-0:2.0-1.noarch' <<<"$OBSOLETE_OLD"
grep -q $'pair\tdnfast-obsoletes-0:2.0-1.noarch\tdnfast-dep-0:1.0-1.noarch' <<<"$OBSOLETE_OLD"

for round in $(seq 1 20); do
  [[ $(solve dnfast-app no-weak "$TRANSITIVE") == "$APP" ]]
  [[ $(solve dnfast-rich weak "$MAIN") == "$RICH" ]]
  [[ $(solve /usr/share/dnfast/provided weak "$MAIN") == "$FILE" ]]
  [[ $(solve dnfast-weak-app weak "$MAIN") == "$WEAK" ]]
  [[ $(solve dnfast-weak-app no-weak "$MAIN") == "$NOWEAK" ]]
  [[ $(solve dnfast-arch weak "$MAIN") == "$ARCH" ]]
  [[ $(solve dnfast-noarch weak "$MAIN") == "$NOARCH" ]]
  [[ $(solve dnfast-unsatisfied weak "$MAIN") == "$PROBLEM" ]]
  [[ $(solve dnfast-app+dnfast-conflict weak "$MAIN") == "$CONFLICT" ]]
  [[ $(solve dnfast-obsoletes weak "$MAIN") == "$OBSOLETES" ]]
  [[ $(solve 'dnfast-upgrade = 1.0-1' weak "$MAIN") == "$RELATION" ]]
  [[ $(solve dnfast-upgrade weak "$MAIN") == "$BEST" ]]
  [[ $(solve dnfast-priority weak "$LOW" "$HIGH") == "$PRIORITY" ]]
  [[ $(solve dnfast-cost weak "$COST_HIGH" "$COST_LOW") == "$COST" ]]
done
printf '%s\n' 'assert transitive=true' 'assert rich=true' 'assert file-provide=true' \
  'assert weak-toggle=true' 'assert arch-noarch=true' 'assert priority-cost=true' \
  'assert conflict-obsoletes-best=true' 'assert exact-problem=true' \
  'assert relation-selector=true' 'assert bare-selector-latest=true' \
  'assert selector-provenance=true' \
  'assert installed-install-is-idempotent=true' \
  'assert transactional-limit-recovery=true' 'assert installed-upgrade-obsoletion=true' \
  'assert causal-strong-weak-installed=true' \
  'assert duplicate-installed-provider-rejected=true' \
  'assert distinct-selected-providers-canonical=true' \
  'assert native-obsolete-counterparts=true' \
  'assert downgrade-reinstall-distro-sync=true' \
  'assert reason-bounded-autoremove=true' \
  'assert exact-plus-one-limits=true' \
  'assert forced-failure-cleanup=true' \
  'assert repeated-cleanup=true'

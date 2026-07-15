#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SOURCE="$ROOT/fixtures/rpm"
OUTPUT=${1:?output directory required}
TOP=$(mktemp -d)
KEYS=$(mktemp -d)
export GNUPGHOME="$KEYS"
trap 'rm -rf "$TOP" "$KEYS"' EXIT INT TERM HUP

need() { command -v "$1" >/dev/null || { echo "fixture-build: missing $1" >&2; exit 1; }; }
for tool in rpmbuild rpmsign rpm rpmkeys createrepo_c gpg sha256sum; do need "$tool"; done
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$OUTPUT"/{repos/{main,alternate,two-repo-main,priority-high,priority-low,cost-low,cost-high},failures,keys}

build() {
  local spec=$1 target=${2:-}
  local args=(-bb --define "_topdir $TOP" --define '_buildhost dnfast.invalid' --define 'source_date_epoch_from_changelog 1')
  [[ -z $target ]] || args+=(--target "$target")
  SOURCE_DATE_EPOCH=1704067200 rpmbuild "${args[@]}" "$SOURCE/$spec" >/dev/null
}

key() {
  local label=$1 expire=$2 fake_time=${3:-} sub_expire=${4:-$2} clock=()
  local home="$KEYS/$label"
  mkdir -m 700 "$home"
  [[ -z $fake_time ]] || clock=(--faked-system-time "$fake_time")
  GNUPGHOME="$home" gpg "${clock[@]}" --batch --passphrase '' --quick-generate-key "dnfast $label <${label}@dnfast.invalid>" ed25519 cert "$expire" >/dev/null 2>&1
  local primary
  primary=$(GNUPGHOME="$home" gpg --batch --with-colons --fingerprint | awk -F: '$1=="fpr" {print $10; exit}')
  GNUPGHOME="$home" gpg "${clock[@]}" --batch --passphrase '' --quick-add-key "$primary" ed25519 sign "$sub_expire" >/dev/null 2>&1
  GNUPGHOME="$home" gpg --batch --armor --export "$primary" >"$OUTPUT/keys/$label.asc"
  GNUPGHOME="$home" gpg --batch --with-colons --fingerprint --fingerprint "$primary" | awk -F: -v label="$label" '$1=="fpr" {n++; print label "\t" (n==1?"primary":"subkey") "\t" $10}' >>"$OUTPUT/fingerprints.tsv"
}

sign_rpm() {
  local home=$1 rpm_file=$2 fake_time=${3:-} subkey signer=()
  subkey=$(GNUPGHOME="$KEYS/$home" gpg --batch --with-colons --fingerprint --fingerprint | awk -F: '$1=="fpr" {n++; if(n==2){print $10; exit}}')
  if [[ -n $fake_time ]]; then
    printf '#!/usr/bin/env bash\nexec /usr/bin/gpg --faked-system-time %s "$@"\n' "$fake_time" >"$TOP/fake-gpg"
    chmod +x "$TOP/fake-gpg"
    signer=(--define "__gpg $TOP/fake-gpg")
  fi
  GNUPGHOME="$KEYS/$home" rpmsign --addsign --define "_openpgp_sign_id $subkey" --define '_openpgp_sign gpg' "${signer[@]}" "$rpm_file" >/dev/null
}

revoke() {
  local label=$1 selector=$2 primary revocation
  primary=$(GNUPGHOME="$KEYS/$label" gpg --batch --with-colons --fingerprint | awk -F: '$1=="fpr" {print $10; exit}')
  if [[ $selector == primary ]]; then
    revocation="$KEYS/$label/openpgp-revocs.d/$primary.rev"
    sed 's/^://' "$revocation" | GNUPGHOME="$KEYS/$label" gpg --batch --import >/dev/null 2>&1
  else
    GNUPGHOME="$KEYS/$label" python3 - "$primary" <<'PY'
import os, pty, select, sys, time
pid, fd = pty.fork()
if pid == 0:
    os.execvp("gpg", ["gpg", "--pinentry-mode", "loopback", "--passphrase", "", "--edit-key", sys.argv[1]])
sent = False
deadline = time.monotonic() + 5
while time.monotonic() < deadline:
    ready, _, _ = select.select([fd], [], [], 0.2)
    if ready:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not sent and b"gpg>" in data:
            os.write(fd, b"key 1\nrevkey\ny\n0\nfixture subkey revocation\n\ny\nsave\n")
            sent = True
    done, status = os.waitpid(pid, os.WNOHANG)
    if done:
        sys.exit(os.waitstatus_to_exitcode(status))
os.kill(pid, 9)
os.waitpid(pid, 0)
sys.exit(0)
PY
  fi
  GNUPGHOME="$KEYS/$label" gpg --batch --armor --export "$primary" >"$OUTPUT/keys/$label.asc"
  local validity
  validity=$(GNUPGHOME="$KEYS/$label" gpg --batch --with-colons --list-keys "$primary" | awk -F: '$1=="pub" {print $2; exit}')
  [[ $selector != subkey || $validity != r ]] || { echo 'primary validity mismatch' >&2; exit 1; }
  validity=$(GNUPGHOME="$KEYS/$label" gpg --batch --with-colons --list-keys "$primary" | awk -F: '$1=="sub" {print $2; exit}')
  [[ $selector != subkey || $validity == r ]] || { echo 'subkey validity mismatch' >&2; exit 1; }
  printf '%s\t%s\n' "$label" "$selector" >>"$OUTPUT/revocations.tsv"
}

rm -rf "$OUTPUT"; mkdir -p "$OUTPUT"/{repos/{main,alternate,two-repo-main,priority-high,priority-low,cost-low,cost-high},failures,keys}; printf 'label\tkind\tfingerprint\n' >"$OUTPUT/fingerprints.tsv"
for spec in relations.spec policies.spec upgrade-v1.spec upgrade-v2.spec vendor-switch-v1.spec vendor-switch.spec config.spec scripts.spec noarch.spec arch-switch.spec; do build "$spec"; done
build arch-switch-v1.spec aarch64
build arch.spec aarch64
build arch.spec x86_64

find "$TOP/RPMS" -type f -name '*.rpm' -exec cp -p {} "$OUTPUT/repos/main/" \;
mv "$OUTPUT/repos/main/dnfast-arch-1.0-1.x86_64.rpm" "$OUTPUT/failures/dnfast-arch-1.0-1.x86_64.rpm"
cp "$OUTPUT/repos/main/dnfast-app-1.0-1.noarch.rpm" "$OUTPUT/failures/unsigned.rpm"
key allowed 2y
key alternate 2y
key expired-primary 1d 1577836800
key expired-subkey 20y 1577836800 1d
key revoked-primary 2y
key revoked-subkey 2y

while IFS= read -r rpm_file; do sign_rpm allowed "$rpm_file"; done < <(find "$OUTPUT/repos/main" -type f -name '*.rpm' | sort)
sign_rpm allowed "$OUTPUT/failures/dnfast-arch-1.0-1.x86_64.rpm"
cp "$OUTPUT/failures/unsigned.rpm" "$OUTPUT/failures/alternate-key.rpm"
sign_rpm alternate "$OUTPUT/failures/alternate-key.rpm"
cp "$OUTPUT/failures/alternate-key.rpm" "$OUTPUT/repos/alternate/dnfast-app-1.0-1.noarch.rpm"
cp "$OUTPUT/repos/main/dnfast-dep-1.0-1.noarch.rpm" "$OUTPUT/repos/two-repo-main/"
for label in expired-primary expired-subkey revoked-primary revoked-subkey; do
  cp "$OUTPUT/failures/unsigned.rpm" "$OUTPUT/failures/$label.rpm"
  if [[ $label == expired-* ]]; then sign_rpm "$label" "$OUTPUT/failures/$label.rpm" 1577836800; else sign_rpm "$label" "$OUTPUT/failures/$label.rpm"; fi
done
revoke revoked-primary primary
revoke revoked-subkey subkey
cp "$OUTPUT/repos/main/dnfast-app-1.0-1.noarch.rpm" "$OUTPUT/failures/corrupt.rpm"
printf '\001' | dd of="$OUTPUT/failures/corrupt.rpm" bs=1 seek=$(( $(stat -c %s "$OUTPUT/failures/corrupt.rpm") - 16 )) conv=notrunc status=none

for repo in priority-high priority-low; do cp "$OUTPUT/repos/main/dnfast-priority-1.0-1.noarch.rpm" "$OUTPUT/repos/$repo/"; done
for repo in cost-low cost-high; do cp "$OUTPUT/repos/main/dnfast-cost-1.0-1.noarch.rpm" "$OUTPUT/repos/$repo/"; done
for repo in main alternate two-repo-main priority-high priority-low cost-low cost-high; do createrepo_c --no-database --simple-md-filenames --revision 1704067200 "$OUTPUT/repos/$repo" >/dev/null; done
subkey=$(awk -F '\t' '$1=="allowed" && $2=="subkey" {print $3}' "$OUTPUT/fingerprints.tsv")
alternate_subkey=$(awk -F '\t' '$1=="alternate" && $2=="subkey" {print $3}' "$OUTPUT/fingerprints.tsv")
for repo in main two-repo-main priority-high priority-low cost-low cost-high; do GNUPGHOME="$KEYS/allowed" gpg --batch --armor --local-user "$subkey" --detach-sign "$OUTPUT/repos/$repo/repodata/repomd.xml"; done
GNUPGHOME="$KEYS/alternate" gpg --batch --armor --local-user "$alternate_subkey" --detach-sign "$OUTPUT/repos/alternate/repodata/repomd.xml"

printf 'sha256\tpath\n' >"$OUTPUT/artifacts.tsv"
find "$OUTPUT" -type f ! -name artifacts.tsv -print0 | sort -z | while IFS= read -r -d '' file; do printf '%s\t%s\n' "$(sha256sum "$file" | awk '{print $1}')" "${file#"$OUTPUT/"}"; done >>"$OUTPUT/artifacts.tsv"
printf 'repo_id\tnevra\tvendor\trequires\tprovides\trecommends\tsuggests\tsupplements\tenhances\tconflicts\tobsoletes\tfile_provides\tconfig_files\tpre\tpost\ttriggers\n' >"$OUTPUT/semantic.tsv"
for repo in main alternate two-repo-main priority-high priority-low cost-low cost-high; do
  find "$OUTPUT/repos/$repo" -maxdepth 1 -type f -name '*.rpm' -print0 | sort -z | while IFS= read -r -d '' file; do
    printf '%s\t' "$repo"
    rpm -qp --qf '%{NEVRA}\t%{VENDOR}\t' "$file" 2>/dev/null
    for relation in requires provides recommends suggests supplements enhances conflicts obsoletes; do value=$(rpm -qp --"$relation" "$file" 2>/dev/null | LC_ALL=C sort -u | paste -sd'|' -); printf '%s\t' "$value"; done
    value=$(rpm -qpl "$file" 2>/dev/null | LC_ALL=C sort -u | paste -sd'|' -); printf '%s\t' "$value"
    rpm -qp --qf '[%{FILENAMES}=%{FILEFLAGS:fflags}|]\t%|PREIN?{1}:{0}|\t%|POSTIN?{1}:{0}|\t%|TRIGGERSCRIPTS?{1}:{0}|\n' "$file" 2>/dev/null
  done
done >>"$OUTPUT/semantic.tsv"
awk -F '\t' 'NR==1 {columns=NF} NF!=columns {exit 1}' "$OUTPUT/semantic.tsv" || { echo 'semantic column count mismatch' >&2; exit 1; }
cut -f1-2 "$OUTPUT/semantic.tsv" >"$OUTPUT/repos.tsv"

rm -rf "$KEYS"; unset GNUPGHOME
if find "$OUTPUT" -type f -print0 | xargs -0 gpg --list-packets 2>/dev/null | grep -q 'secret key packet'; then echo 'fixture-build: secret key packet retained' >&2; exit 1; fi
if find "$OUTPUT" -type d -name 'private-keys-v1.d' -o -name 'openpgp-revocs.d' | grep -q .; then echo 'fixture-build: private keyring retained' >&2; exit 1; fi

#!/usr/bin/env bash
set -euo pipefail
out=${1:?output directory required}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM HUP
if ! command -v rpmbuild >/dev/null || ! command -v rpmsign >/dev/null; then
  mkdir -p "$work/tools"
  for package in rpm-build rpm-sign; do
    rpm2archive "/tmp/rpms/$package-6.0.1-2.fc44.aarch64.rpm" | tar -xz -C "$work/tools"
  done
  export PATH="$work/tools/usr/bin:$PATH"
fi
mkdir -m 700 -p "$work/gnupg" "$work/top"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} "$out"
rpm_config=()
[[ ! -d $work/tools/usr/lib/rpm ]] || rpm_config=(--define "_rpmconfigdir $work/tools/usr/lib/rpm")
export GNUPGHOME="$work/gnupg"
gpg --batch --passphrase '' --quick-generate-key 'dnfast collision <collision@dnfast.invalid>' ed25519 cert 1d >/dev/null 2>&1
primary=$(gpg --batch --with-colons --fingerprint | awk -F: '$1=="fpr" {print $10; exit}')
gpg --batch --passphrase '' --quick-add-key "$primary" ed25519 sign 1d >/dev/null 2>&1
signer=$(gpg --batch --with-colons --fingerprint --fingerprint | awk -F: '$1=="fpr" {n++; if(n==2){print $10; exit}}')
gpg --batch --armor --export "$primary" >"$out/key.asc"
for name in provider collision; do
  content=$name
  spec="$work/top/SPECS/$name.spec"
  printf '%s\n' "Name: dnfast-live-$name" 'Version: 1.0' 'Release: 1' \
    "Summary: dnfast live $name" 'License: MIT' 'BuildArch: noarch' '%description' \
    "$name fixture" '%prep' '%build' '%install' \
    'mkdir -p %{buildroot}/usr/share/dnfast' \
    "printf '$content\\n' > %{buildroot}/usr/share/dnfast/live-collision" \
    '%files' '/usr/share/dnfast/live-collision' >"$spec"
  rpmbuild -bb "${rpm_config[@]}" --define "_topdir $work/top" "$spec" >/dev/null
  rpm_file=$(find "$work/top/RPMS" -name "dnfast-live-$name-*.rpm")
  GNUPGHOME="$GNUPGHOME" rpmsign --addsign --define "_openpgp_sign_id $signer" \
    --define '_openpgp_sign gpg' "$rpm_file" >/dev/null
  cp "$rpm_file" "$out/$name.rpm"
done

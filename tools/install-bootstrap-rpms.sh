#!/usr/bin/env bash
# Install bootstrap RPMs only when the installed package is byte-for-byte the
# same NEVRA as the supplied RPM.  This makes an interrupted QEMU bootstrap
# retryable without treating a different installed version as acceptable.
set -euo pipefail

die() {
  printf 'bootstrap_rpm=error:%s\n' "$*" >&2
  exit 1
}

install_bootstrap_rpm() {
  local rpm_file=$1 name expected installed query_status

  # A failed query must never be mistaken for "not installed" because that
  # would turn an RPM database error into an install attempt.
  rpm --verifydb
  name=$(rpm -qp --qf '%{NAME}' "$rpm_file")
  expected=$(rpm -qp --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' "$rpm_file")

  set +e
  installed=$(rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' "$name")
  query_status=$?
  set -e
  case $query_status in
    0)
      if [[ $installed == "$expected" ]]; then
        printf 'bootstrap_rpm=already-installed:%s\n' "$expected"
        return
      fi
      die "installed-nevra-mismatch expected=$expected installed=$installed"
      ;;
    1)
      # `rpm --verifydb` above succeeded, so the documented query status 1 is
      # the only status accepted as an absent package.
      ;;
    *)
      die "query-failed name=$name status=$query_status"
      ;;
  esac

  sudo rpm --nodeps -i "$rpm_file"
  rpm --verifydb
  installed=$(rpm -q --qf '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}' "$name") \
    || die "post-install-query-failed name=$name"
  [[ $installed == "$expected" ]] \
    || die "post-install-nevra-mismatch expected=$expected installed=$installed"
  printf 'bootstrap_rpm=installed:%s\n' "$expected"
}

(($# > 0)) || die 'no RPM files supplied'
for rpm_file in "$@"; do
  install_bootstrap_rpm "$rpm_file"
done

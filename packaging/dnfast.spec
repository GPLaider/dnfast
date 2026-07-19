Name:           dnfast
Version:        0.1.0
Release:        1%{?dist}
Summary:        Independent fail-closed RPM package manager for Fedora

License:        GPL-2.0-or-later
URL:            https://github.com/GPLaider/dnfast
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.gz

# The native ABI and full host/KVM gates are currently verified only on this architecture.
ExclusiveArch:  x86_64

BuildRequires:  cargo >= 1.85
BuildRequires:  rust >= 1.85
BuildRequires:  clang
BuildRequires:  gcc
BuildRequires:  nettle-devel
BuildRequires:  pkgconf-pkg-config
BuildRequires:  pkgconfig(libzstd)
BuildRequires:  pkgconfig(libsolv) = 0.7.39
BuildRequires:  pkgconfig(modulemd-2.0) >= 2.15.2
BuildRequires:  pkgconfig(rpm) = 6.0.1
BuildRequires:  systemd-rpm-macros
BuildRequires:  zstd

Requires:       libdnf5
Requires:       rpm
Requires:       sqlite-libs
Requires:       systemd

%description
dnfast is an independent RPM package manager for Fedora. It verifies rpm-md
metadata and selected RPMs, resolves transactions directly with libsolv, and
applies approved transactions directly with librpm. Its supported command
surface is intentionally smaller than DNF5 and fails closed for unsupported
operations.

%prep
%autosetup -n %{name}-%{version}
tar -xf %{SOURCE1}
mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"

[net]
offline = true
EOF

%build
export CARGO_HOME=%{_builddir}/dnfast-cargo-home
export CARGO_PROFILE_RELEASE_DEBUG=2
export CARGO_PROFILE_RELEASE_STRIP=none
export DNFAST_NATIVE_REAL=1
export ZSTD_SYS_USE_PKG_CONFIG=1
cargo build --offline --locked --release -p dnfast-cli -p dnfast-executor --bins

%check
export CARGO_HOME=%{_builddir}/dnfast-cargo-home
export DNFAST_NATIVE_REAL=1
export ZSTD_SYS_USE_PKG_CONFIG=1
cargo test --offline --locked --workspace --all-targets -- --test-threads=1

%install
install -Dpm0755 target/release/dnfast %{buildroot}%{_bindir}/dnfast
install -Dpm0755 target/release/dnfast-executor %{buildroot}%{_libexecdir}/dnfast-executor
install -Dpm0755 target/release/dnfastd %{buildroot}%{_libexecdir}/dnfastd
install -Dpm0644 packaging/dnfastd.service %{buildroot}%{_unitdir}/dnfastd.service

%post
%systemd_post dnfastd.service

%preun
%systemd_preun dnfastd.service

%postun
%systemd_postun_with_restart dnfastd.service

%files
%license LICENSE
%doc README.md IMPORT_PROVENANCE.md docs/architecture.md docs/safety.md
%{_bindir}/dnfast
%{_libexecdir}/dnfast-executor
%{_libexecdir}/dnfastd
%{_unitdir}/dnfastd.service

%changelog
* Mon Jul 20 2026 GPLaider <GPLaider@users.noreply.github.com> - 0.1.0-1
- Initial COPR technical preview for Fedora 44 x86_64

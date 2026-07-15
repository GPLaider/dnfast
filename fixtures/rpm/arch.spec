Name: dnfast-arch
Version: 1.0
Release: 1
Summary: Architecture fixture
License: MIT
%description
Architecture-specific candidate.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
printf '%s\n' '%{_target_cpu}' > %{buildroot}/usr/share/dnfast/arch
%files
%dir /usr/share/dnfast
/usr/share/dnfast/arch

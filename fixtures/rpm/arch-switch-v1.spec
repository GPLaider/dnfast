Name: dnfast-arch-switch
Version: 1.0
Release: 1
Summary: Architecture switch baseline
License: MIT
%description
Architecture-specific installed baseline.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
printf '%s\n' '%{_target_cpu}' > %{buildroot}/usr/share/dnfast/arch-switch
%files
%dir /usr/share/dnfast
/usr/share/dnfast/arch-switch

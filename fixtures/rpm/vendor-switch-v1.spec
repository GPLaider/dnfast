Name: dnfast-vendor-switch
Version: 1.0
Release: 1
Summary: Vendor switch baseline
License: MIT
BuildArch: noarch
Vendor: Dnfast Vendor A
%description
Original vendor baseline.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
printf 'vendor-a\n' > %{buildroot}/usr/share/dnfast/vendor-switch
%files
%dir /usr/share/dnfast
/usr/share/dnfast/vendor-switch

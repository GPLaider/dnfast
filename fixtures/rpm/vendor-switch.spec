Name: dnfast-vendor-switch
Version: 2.0
Release: 1
Summary: Vendor switch fixture
License: MIT
BuildArch: noarch
Vendor: Dnfast Vendor B
%description
Alternate vendor candidate.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
printf 'vendor-b\n' > %{buildroot}/usr/share/dnfast/vendor-switch
%files
%dir /usr/share/dnfast
/usr/share/dnfast/vendor-switch

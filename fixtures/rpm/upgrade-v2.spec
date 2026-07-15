Name: dnfast-upgrade
Version: 2.0
Release: 1
Summary: Upgrade fixture v2
License: MIT
BuildArch: noarch
Vendor: Dnfast Original
%description
Second upgrade version.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
printf 'v2\n' > %{buildroot}/usr/share/dnfast/upgrade
%files
%dir /usr/share/dnfast
/usr/share/dnfast/upgrade

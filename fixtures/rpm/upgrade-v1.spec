Name: dnfast-upgrade
Version: 1.0
Release: 1
Summary: Upgrade fixture v1
License: MIT
BuildArch: noarch
Vendor: Dnfast Original
%description
First upgrade version.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
printf 'v1\n' > %{buildroot}/usr/share/dnfast/upgrade
%files
%dir /usr/share/dnfast
/usr/share/dnfast/upgrade

Name: dnfast-config
Version: 1.0
Release: 1
Summary: Configuration fixture
License: MIT
BuildArch: noarch
%description
Configuration preservation fixture.
%prep
%build
%install
mkdir -p %{buildroot}/etc/dnfast
printf 'fixture=true\n' > %{buildroot}/etc/dnfast/fixture.conf
%files
%config(noreplace) /etc/dnfast/fixture.conf

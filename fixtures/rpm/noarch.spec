Name: dnfast-noarch
Version: 1.0
Release: 1
Summary: Architecture-neutral fixture
License: MIT
BuildArch: noarch
%description
Architecture-neutral candidate.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
: > %{buildroot}/usr/share/dnfast/noarch
%files
%dir /usr/share/dnfast
/usr/share/dnfast/noarch

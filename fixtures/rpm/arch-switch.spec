Name: dnfast-arch-switch
Version: 2.0
Release: 1
Summary: Architecture switch fixture
License: MIT
BuildArch: noarch
%description
Architecture-switch candidate.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
: > %{buildroot}/usr/share/dnfast/arch-switch
%files
%dir /usr/share/dnfast
/usr/share/dnfast/arch-switch

Name: dnfast-policies
Version: 1.0
Release: 1
Summary: dnfast policy fixtures
License: MIT
BuildArch: noarch

%description
Policy fixture source.

%package -n dnfast-conflict
Summary: Conflict fixture
Conflicts: dnfast-dep
%description -n dnfast-conflict
Conflicts with the dependency.

%package -n dnfast-obsoletes
Version: 2.0
Summary: Obsoletes fixture
Obsoletes: dnfast-dep < 2.0
Provides: dnfast-dep = 2.0
%description -n dnfast-obsoletes
Obsoletes the dependency.

%package -n dnfast-priority
Summary: Priority tie fixture
Provides: dnfast-tie = 1.0
%description -n dnfast-priority
Priority tie fixture.

%package -n dnfast-cost
Summary: Cost tie fixture
Provides: dnfast-tie = 1.0
%description -n dnfast-cost
Cost tie fixture.

%package -n dnfast-protected
Summary: Protected fixture
%description -n dnfast-protected
Protected policy fixture.

%package -n dnfast-installonly
Summary: Installonly fixture
Provides: installonlypkg(kernel)
%description -n dnfast-installonly
Installonly policy fixture.

%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
for file in conflict obsoletes priority cost protected installonly; do printf '%s\n' "$file" > "%{buildroot}/usr/share/dnfast/$file"; done

%files -n dnfast-conflict
%dir /usr/share/dnfast
/usr/share/dnfast/conflict
%files -n dnfast-obsoletes
%dir /usr/share/dnfast
/usr/share/dnfast/obsoletes
%files -n dnfast-priority
%dir /usr/share/dnfast
/usr/share/dnfast/priority
%files -n dnfast-cost
%dir /usr/share/dnfast
/usr/share/dnfast/cost
%files -n dnfast-protected
%dir /usr/share/dnfast
/usr/share/dnfast/protected
%files -n dnfast-installonly
%dir /usr/share/dnfast
/usr/share/dnfast/installonly

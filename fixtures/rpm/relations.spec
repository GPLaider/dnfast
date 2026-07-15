Name: dnfast-relations
Version: 1.0
Release: 1
Summary: dnfast relation fixtures
License: MIT
BuildArch: noarch

%description
Relation fixture source.

%package -n dnfast-dep
Summary: Required dependency
Provides: dnfast-capability = 1.0
%description -n dnfast-dep
Required dependency.

%package -n dnfast-app
Summary: Application
Requires: dnfast-dep >= 1.0
%description -n dnfast-app
Application requiring dnfast-dep.

%package -n dnfast-rich
Summary: Rich dependency
Requires: (dnfast-capability >= 1.0 if dnfast-dep)
%description -n dnfast-rich
Rich dependency fixture.

%package -n dnfast-unsatisfied
Summary: Unsatisfied dependency
Requires: dnfast-never-provided >= 9
%description -n dnfast-unsatisfied
Unsatisfied dependency fixture.

%package -n dnfast-weak-app
Summary: Weak dependency
Recommends: dnfast-dep
Suggests: dnfast-file-provider
Supplements: dnfast-app
Enhances: dnfast-rich
%description -n dnfast-weak-app
Weak dependency fixture.

%package -n dnfast-file-provider
Summary: File provider
%description -n dnfast-file-provider
Provides a required path.

%package -n dnfast-file-collision
Summary: File collision
%description -n dnfast-file-collision
Collides with file provider.

%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
printf 'dep\n' > %{buildroot}/usr/share/dnfast/dep
printf 'app\n' > %{buildroot}/usr/share/dnfast/app
printf 'rich\n' > %{buildroot}/usr/share/dnfast/rich
printf 'unsatisfied\n' > %{buildroot}/usr/share/dnfast/unsatisfied
printf 'weak\n' > %{buildroot}/usr/share/dnfast/weak
printf 'provider\n' > %{buildroot}/usr/share/dnfast/provided

%files -n dnfast-dep
%dir /usr/share/dnfast
/usr/share/dnfast/dep
%files -n dnfast-app
%dir /usr/share/dnfast
/usr/share/dnfast/app
%files -n dnfast-rich
%dir /usr/share/dnfast
/usr/share/dnfast/rich
%files -n dnfast-unsatisfied
%dir /usr/share/dnfast
/usr/share/dnfast/unsatisfied
%files -n dnfast-weak-app
%dir /usr/share/dnfast
/usr/share/dnfast/weak
%files -n dnfast-file-provider
%dir /usr/share/dnfast
/usr/share/dnfast/provided
%files -n dnfast-file-collision
%dir /usr/share/dnfast
/usr/share/dnfast/provided

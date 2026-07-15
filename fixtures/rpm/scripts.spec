Name: dnfast-scripts
Version: 1.0
Release: 1
Summary: Script failure fixtures
License: MIT
BuildArch: noarch
%description
Script failure fixture source.
%package -n dnfast-pre-failure
Summary: Pre failure
%description -n dnfast-pre-failure
Fails during pre.
%package -n dnfast-post-failure
Summary: Post failure
%description -n dnfast-post-failure
Fails during post.
%package -n dnfast-trigger-failure
Summary: Trigger failure
%description -n dnfast-trigger-failure
Fails in a trigger.
%prep
%build
%install
mkdir -p %{buildroot}/usr/share/dnfast
for file in pre-failure post-failure trigger-failure; do : > "%{buildroot}/usr/share/dnfast/$file"; done
%pre -n dnfast-pre-failure
exit 41
%post -n dnfast-post-failure
exit 42
%triggerin -n dnfast-trigger-failure -- dnfast-app
exit 43
%files -n dnfast-pre-failure
%dir /usr/share/dnfast
/usr/share/dnfast/pre-failure
%files -n dnfast-post-failure
%dir /usr/share/dnfast
/usr/share/dnfast/post-failure
%files -n dnfast-trigger-failure
%dir /usr/share/dnfast
/usr/share/dnfast/trigger-failure

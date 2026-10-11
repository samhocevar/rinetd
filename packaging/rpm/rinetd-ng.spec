Name: rinetd-ng
Version: 1.0
Release: 0.1.rc1%{?dist}
Summary: Minimal TCP and UDP port redirection daemon
License: GPL-2.0-or-later
URL: https://github.com/samhocevar/rinetd
Source0: %{name}-%{version}.tar.gz
BuildRequires: gcc
BuildRequires: make
BuildRequires: autoconf
BuildRequires: automake
BuildRequires: python3
BuildRequires: systemd-rpm-macros
Requires(pre): shadow-utils
%description
rinetd-ng development release, derived from rinetd by Thomas Boutell and Sam Hocevar.
%prep
%setup -q
%build
./tools/build.sh
%install
install -Dpm 0755 upstream/rinetd %{buildroot}%{_sbindir}/rinetd
install -Dpm 0755 bin/rinetd-ng-config-check %{buildroot}%{_libexecdir}/rinetd-ng-config-check
install -Dpm 0644 packaging/rinetd-ng.service %{buildroot}%{_unitdir}/rinetd-ng.service
install -Dpm 0640 config/rinetd.conf.example %{buildroot}%{_sysconfdir}/rinetd.conf
%pre
getent group rinetd >/dev/null || groupadd -r rinetd
getent passwd rinetd >/dev/null || useradd -r -g rinetd -s /sbin/nologin -M rinetd
%post
%systemd_post rinetd-ng.service
%preun
%systemd_preun rinetd-ng.service
%postun
%systemd_postun_with_restart rinetd-ng.service
%files
%license upstream/COPYING
%doc README.md
%{_sbindir}/rinetd
%{_libexecdir}/rinetd-ng-config-check
%{_unitdir}/rinetd-ng.service
%config(noreplace) %attr(0640,root,rinetd) %{_sysconfdir}/rinetd.conf
%changelog
* Thu Oct 08 2026 rinetd-ng contributors - 1.0-0.1.rc1
- Initial RPM packaging of the development release.

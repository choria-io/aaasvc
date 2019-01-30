%define debug_package %{nil}
%define pkgname {{cpkg_name}}
%define version {{cpkg_version}}
%define bindir {{cpkg_bindir}}
%define etcdir {{cpkg_etcdir}}
%define release {{cpkg_release}}
%define dist {{cpkg_dist}}
%define binary {{cpkg_binary}}
%define tarball {{cpkg_tarball}}

Name: %{pkgname}
Version: %{version}
Release: %{release}.%{dist}
Summary: The Choria AAA Service
License: Apache-2.0
URL: https://choria.io
Group: System Tools
Packager: R.I.Pienaar <rip@devco.net>
Source0: %{tarball}
BuildRoot: %{_tmppath}/%{pkgname}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires(pre): /usr/sbin/useradd, /usr/bin/getent, initscripts
Requires(postun): /usr/sbin/userdel

%description
JWT Token based authentication and signing service allowing Choria
users to authenticate to a service rather than all requiring a certificate

https://github.com/choria-io/aaasvc

%prep
%setup -q

%build

%install
rm -rf %{buildroot}
%{__install} -d -m0755  %{buildroot}/etc/sysconfig
%{__install} -d -m0755  %{buildroot}/etc/init.d
%{__install} -d -m0755  %{buildroot}/etc/logrotate.d
%{__install} -d -m0755  %{buildroot}%{bindir}
%{__install} -d -m0755  %{buildroot}%{etcdir}
%{__install} -d -m0755  %{buildroot}/var/log/%{pkgname}
%{__install} -d -m0756  %{buildroot}/var/run/%{pkgname}
%{__install} -m0644 dist/aaasvc.init %{buildroot}/etc/init.d/%{pkgname}
%{__install} -m0644 dist/aaasvc-logrotate %{buildroot}/etc/logrotate.d/%{pkgname}
%{__install} -m0644 dist/sysconfig %{buildroot}/etc/sysconfig/%{pkgname}
%{__install} -m0755 %{binary} %{buildroot}%{bindir}/%{pkgname}
%{__install} -m0755 dist/config.json %{buildroot}%{etcdir}/config.json
touch %{buildroot}/var/log/%{pkgname}/%{pkgname}.log

%clean
rm -rf %{buildroot}

%post
/sbin/chkconfig --add %{pkgname} || :

%postun
if [ "$1" -ge 1 ]; then
  /sbin/service %{pkgname} condrestart &>/dev/null || :
fi

%preun
if [ "$1" = 0 ] ; then
  /sbin/service %{pkgname} stop > /dev/null 2>&1 || :
  /sbin/chkconfig --del %{pkgname} || :
  /usr/sbin/userdel aaasvc || :
fi

%pre
/usr/bin/getent group aaasvc || /usr/sbin/groupadd -r aaasvc
/usr/bin/getent passwd aaasvc || /usr/sbin/useradd -r -s /sbin/nologin -d /home/aaasvc -g aaasvc -c "Choria AAA Service" aaasvc

%files
%{bindir}/aaasvc
/etc/logrotate.d/%{pkgname}
%attr(755, root, root)/etc/init.d/%{pkgname}
%attr(755, aaasvc, aaasvc)/var/run/%{pkgname}
%attr(755, aaasvc, aaasvc)/var/log/%{pkgname}
%config(noreplace) /etc/sysconfig/%{pkgname}
%config(noreplace) %{etcdir}

%changelog
* Wed Jan 30 2019 R.I.Pienaar <rip@devco.net>
- Initial Release

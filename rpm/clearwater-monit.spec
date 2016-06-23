Name: clearwater-monit
Summary: Process monitor and restart utility
BuildRequires: flex bison openssl-devel pam-devel

%include %{rootdir}/build-infra/cw-rpm.spec.inc

%description
Monit is a utility for managing and monitoring processes,
files, directories and filesystems on a Unix system. Monit conducts
automatic maintenance and repair and can execute meaningful causal
actions in error situations.

%install
. %{rootdir}/build-infra/cw-rpm-utils clearwater-monit %{rootdir} %{buildroot}
setup_buildroot
install_to_buildroot < %{rootdir}/debian/clearwater-monit.install
dirs_to_buildroot < %{rootdir}/debian/clearwater-monit.dirs
copy_to_buildroot debian/clearwater-monit.service /etc/systemd/system
copy_to_buildroot debian/clearwater-monit.logrotate /etc/logrotate.d clearwater-monit
copy_to_buildroot debian/clearwater-monit.default /etc/default clearwater-monit
build_files_list > clearwater-monit.files

%post
if [ "$1" == 1 ] ; then
  /usr/share/clearwater/clearwater-monit/install/clearwater-monit.postinst
fi
systemctl enable clearwater-monit
systemctl start clearwater-monit

%preun
# Uninstall, not upgrade
if [ "$1" == 0 ] ; then
  systemctl stop clearwater-monit
  systemctl disable clearwater-monit
fi

%files -f clearwater-monit.files

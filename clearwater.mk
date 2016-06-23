PKG_COMPONENT := clearwater-monit
PKG_MAJOR_VERSION := 5.8.1
PKG_NAMES := clearwater-monit

include build-infra/cw-deb.mk
include build-infra/cw-rpm.mk

.PHONY: configure
configure:
	./bootstrap && ./configure

.PHONY: deb-build-monit
deb-build-monit: configure
	echo -e "${DEB_COMPONENT} (${DEB_MAJOR_VERSION}-${DEB_MINOR_VERSION}) unstable; urgency=low\n" >debian/changelog
	echo -e "  * build from revision $$(git rev-parse HEAD)\n" >>debian/changelog
	echo -e " -- $(CW_SIGNER_REAL) <$(CW_SIGNER)>  $$(date -R)\n" >>debian/changelog
	debuild --no-lintian -b -uc -us

.PHONY: deb
deb: deb-build-monit deb-move

.PHONY: makeall
makeall:
	make all

.PHONY: rpm
rpm: configure makeall rpm-only

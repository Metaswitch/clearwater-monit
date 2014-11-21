DEB_COMPONENT := clearwater-monit
DEB_MAJOR_VERSION := 5.9${DEB_VERSION_QUALIFIER}
DEB_NAMES := clearwater-monit

include build-infra/cw-deb.mk

.PHONY: deb-build-monit
deb-build-monit:
	echo "${DEB_COMPONENT} (${DEB_VERSION}) unstable; urgency=low" >debian/changelog
	echo " * build from revision $$(git rev-parse HEAD)" >>debian/changelog;\
	echo " -- $(CW_SIGNER_REAL) <$(CW_SIGNER)> $$(date -R)" >>debian/changelog
	debuild --no-lintian -b -uc -us

.PHONY: deb
deb: deb-build-monit deb-move

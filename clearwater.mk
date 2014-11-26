DEB_COMPONENT := clearwater-monit
DEB_MAJOR_VERSION := 5.10${DEB_VERSION_QUALIFIER}
DEB_NAMES := clearwater-monit

include build-infra/cw-deb.mk

.PHONY: deb-build-monit
deb-build-monit:
	echo -e "${DEB_COMPONENT} (${DEB_VERSION}) unstable; urgency=low\n" >debian/changelog
	echo -e "  * build from revision $$(git rev-parse HEAD)\n" >>debian/changelog
	echo -e " -- $(CW_SIGNER_REAL) <$(CW_SIGNER)>  $$(date -R)\n" >>debian/changelog
	debuild --no-lintian -b -uc -us

.PHONY: deb
deb: deb-build-monit deb-move

.PHONY: all clean deb scp

VERSION=1.0.0
FBASE=micronets-gw
SBASE=filesystem
IBASE=/opt

SCPHOST=u16

VDIR=$(FBASE)-$(VERSION)
DEBFILE=$(VDIR).deb
DEBDIR=$(VDIR)/DEBIAN
IDIR=$(VDIR)$(IBASE)/$(FBASE)


all: clean deb

clean:
	rm -rf $(VDIR) > /dev/null 2>&1 || true
	rm $(FBASE)*.deb > /dev/null 2>&1 || true

deb: $(DEBFILE)

$(DEBFILE):
	mkdir $(VDIR)
	(cd $(SBASE); tar cf - .) | (cd  $(VDIR); tar xf -) 
	date -Iseconds > $(IDIR)/BUILDTIME
	uname -a > $(IDIR)/BUILDHOST
	echo "$(VERSION)" > $(IDIR)/VERSION
	echo "Version: $(VERSION)" >> $(VDIR)/DEBIAN/control
	dpkg-deb --build $(VDIR)
	rm -rf $(VDIR)
	dpkg-deb --info $(DEBFILE)
	ls -l $(DEBFILE)

scp: $(DEBFILE)
	scp $(DEBFILE) $(SCPHOST):

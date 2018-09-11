VERSION=1.0.0
FBASE=micronets-gw
IBASE=/opt
SCPHOST=u16

VDIR=$(FBASE)-$(VERSION)
DEBFILE=$(VDIR).deb
DEBDIR=$(VDIR)/DEBIAN
IDIR=$(VDIR)$(IBASE)/$(FBASE)

all: $(DEBFILE)

clean:
	rm -rf $(VDIR) > /dev/null 2>&1 || true
	rm $(FBASE)*.deb > /dev/null 2>&1 || true

scp: $(DEBFILE)
	scp $(DEBFILE) $(SCPHOST):

$(DEBFILE):
	mkdir $(VDIR)
	(cd $(FBASE); tar cf - .) | (cd  $(VDIR); tar xf -) 
	date -Iseconds > $(IDIR)/BUILDTIME
	uname -a > $(IDIR)/BUILDHOST
	echo "$(VERSION)" > $(IDIR)/VERSION
	echo "Version: $(VERSION)" >> $(VDIR)/DEBIAN/control
	dpkg-deb --build $(VDIR)
	rm -rf $(VDIR)
	dpkg-deb --info $(DEBFILE)
	ls -l $(DEBFILE)

.PHONY: all clean deb scp

VERSION=1.0.0
FBASE=micronets-gw
SDIRS=filesystem ../micronets-gw-service
IBASE=/opt

SCPHOST=u16

VDIR=$(FBASE)-$(VERSION)
DEBFILE=$(VDIR).deb
DEBDIR=target/$(DEBFILE)
IDIR=$(VDIR)$(IBASE)/$(FBASE)

all: clean deb

clean:
	rm -rf target  > /dev/null 2>&1 || true
	rm -rf $(VDIR) > /dev/null 2>&1 || true

deb: $(DEBFILE)

$(DEBFILE):
	mkdir -p target/ar
	mkdir $(VDIR)
	$(foreach var,$(SDIRS),(cd $(var); tar cf - .) | (cd $(VDIR); tar xf -);)
	date -Iseconds > $(IDIR)/BUILDTIME
	uname -a > $(IDIR)/BUILDHOST
	echo "$(VERSION)" > $(IDIR)/VERSION
	echo "Version: $(VERSION)" >> $(VDIR)/DEBIAN/control
	dpkg-deb --build $(VDIR)
	rm -rf $(VDIR)
	dpkg-deb --info $(DEBDIR)
	ls -l $(DEBDIR)
	(cd target/ar; ar x ../$(DEBFILE))
	tar tf target/ar/data.tar.xz | sort | less

scp: $(DEBFILE)
	scp $(DEBFILE) $(SCPHOST):

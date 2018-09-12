.PHONY: all clean distclean deb scp

VERSION=1.0.0
FBASE=micronets-gw
SDIRS=filesystem ../micronets-gw-service
IBASE=/opt

TARGETDIR=target
ARDIR=$(TARGETDIR)/ar

SCPHOST=u16

VDIR=$(FBASE)-$(VERSION)
DEBFILE=$(VDIR).deb
DEBPATH=$(TARGETDIR)/$(DEBFILE)
IDIR=$(VDIR)$(IBASE)/$(FBASE)

all: clean deb

clean:
	rm -rf $(VDIR)      > /dev/null 2>&1
	rm -rf $(TARGETDIR) > /dev/null 2>&1

distclean: clean

deb: $(DEBPATH)

$(DEBPATH):
	# Create directories
	mkdir $(VDIR) # Create debian package construction directory
	mkdir $(TARGETDIR) # Create output directory.
	mkdir $(ARDIR) # Create debug archive output directory.

	# Move the source filesystems to the package construction directory.
	$(foreach var,$(SDIRS),(cd $(var); tar cf - .) | (cd $(VDIR); tar xf -);)

	# Create the build metadata files.
	date -Iseconds > $(IDIR)/BUILDTIME
	uname -a > $(IDIR)/BUILDHOST
	echo "$(VERSION)" > $(IDIR)/VERSION

	# Append version to debian control file.
	echo "Version: $(VERSION)" >> $(VDIR)/DEBIAN/control

	# Build the $(DEBFILE).
	dpkg-deb --build $(VDIR)

  # Move the $(DEBFILE) to its final location in the $(TARGETDIR) directory.
	mv $(DEBFILE) $(DEBPATH)

  # Remove the package constuction directory as it is no longer needed.
	rm -rf $(VDIR)

	# DEBUG: Dump the $(DEBFILE) info.
	dpkg-deb --info $(DEBPATH)

  # DEBUG: Dump out the contents of the data and control archives in the resultant package file $(DEBPATH).
	(cd $(ARDIR); ar x ../$(DEBFILE))
	tar tf $(ARDIR)/data.tar.xz    | sort > $(TARGETDIR)/data.lst
	tar tf $(ARDIR)/control.tar.gz | sort > $(TARGETDIR)/control.lst
	echo "The $(ARDIR) directory is for debugging purposes: Do not distribute.\n\nContains un-archived contents of $(DEBFILE)." > $(ARDIR)/README

scp: $(DEBPATH)
	scp $(DEBPATH) $(SCPHOST):

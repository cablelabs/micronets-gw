.PHONY: all clean distclean deb scp

VERSION=1.0.65
DIST=U18.04
FBASE=micronets-gw
SDIRS=../filesystem
IBASE=/opt

TARGETDIR=target
ARDIR=$(TARGETDIR)/ar

SCPUSER=root
SCPHOST=ovs01

PUSHUSER=cpratt

VDIR=$(FBASE)-$(VERSION)-$(DIST)
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

	# Copy the source filesystems SDIRS to the package construction directory.
	$(foreach var,$(SDIRS),(cd $(var); tar cf - .) | (cd $(VDIR); tar xf -);)

	# Copy the micronets-gw-service under $(VDIR)/opt/$(FBASE) to the package construction directory.
	(cd ../micronets-gw-service; tar cf - .) | (cd $(VDIR)/opt/$(FBASE); tar xf -);
	rm -rf $(VDIR)/opt/$(FBASE)/.idea

	# Create the build metadata files.
	date -Iseconds > $(IDIR)/BUILDTIME
	uname -a > $(IDIR)/BUILDHOST
	echo "$(VERSION)" > $(IDIR)/VERSION

	# Append version to debian control file.
	echo "Version: $(VERSION)" >> $(VDIR)/DEBIAN/control

	# Build the $(DEBFILE).
	fakeroot dpkg-deb --build $(VDIR)

  # Move the $(DEBFILE) to its final location in the $(TARGETDIR) directory.
	mv $(DEBFILE) $(DEBPATH)

  # Remove the package constuction directory as it is no longer needed.
	rm -rf $(VDIR)

	# DEBUG: Dump the $(DEBFILE) info.
	dpkg-deb --info $(DEBPATH)

  # DEBUG: Dump out the contents of the data and control archives in the resultant package file $(DEBPATH).
	(cd $(ARDIR); ar x ../$(DEBFILE))
	tar tf $(ARDIR)/data.tar.?z    | sort > $(TARGETDIR)/data.lst
	tar tf $(ARDIR)/control.tar.?z | sort > $(TARGETDIR)/control.lst
	echo "The $(ARDIR) directory is for debugging purposes: Do not distribute.\n\nContains un-archived contents of $(DEBFILE)." > $(ARDIR)/README

scp: $(DEBPATH)
	scp $(DEBPATH) $(SCPUSER)@$(SCPHOST):

push-artifacts: $(DEBPATH)
	curl -u$(PUSHUSER) -XPUT \
		"https://community.cablelabs.com/mvn/micronets-dpkg/pool/$(DEBFILE);deb.distribution=xenial;deb.component=main;deb.architecture=all" \
		-H "X-Checksum-Sha1: $(shell sha1sum $(DEBPATH) | cut -d' ' -f1)" \
		-T "$(DEBPATH)"

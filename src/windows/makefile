#
# Makefile that recurses into cns subdirectory.
#
all::
	@echo Making in windows\cns
	cd cns
	-$(MAKE) -$(MAKEFLAGS) LIBCMD=$(LIBCMD)
	cd ..

clean::
	@echo Making clean in windows\cns
	cd cns
	-$(MAKE) -$(MAKEFLAGS) clean
	cd ..


#
# Makefile that recurses into cns subdirectory.
#
all::
	@echo Making in windows\cns
	cd cns
	-$(MAKE) -$(MAKEFLAGS) LIBCMD=$(LIBCMD)
	@echo Making in windows\wintel
	cd ..\wintel
	-$(MAKE) -$(MAKEFLAGS) LIBCMD=$(LIBCMD)
	@echo Making in windows\gss
	cd ..\gss
	-$(MAKE) -$(MAKEFLAGS) LIBCMD=$(LIBCMD)
	cd ..

clean::
	@echo Making clean in windows\cns
	cd cns
	-$(MAKE) -$(MAKEFLAGS) clean
	@echo Making clean in windows\wintel
	cd ..\wintel
	-$(MAKE) -$(MAKEFLAGS) clean
	@echo Making clean in windows\gss
	cd ..\gss
	-$(MAKE) -$(MAKEFLAGS) clean
	cd ..


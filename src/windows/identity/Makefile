#
# Copyright (c) 2004 Massachusetts Institute of Technology
# Copyright (c) 2006 Secure Endpoints Inc.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

!ifdef ETAGRUN
all: finale doc
!else
all: finale
!endif

MODULE=all
!include <config/Makefile.w32>

!ifndef CLEANRUN
!ifndef TESTRUN
!ifndef ETAGRUN

# Define KH_NO_WX if the build should not fail on warnings.  The
# default is to treat warnings as errors.

#RMAKE=$(MAKECMD) /nologo all KH_NO_WX=1
RMAKE=$(MAKECMD) /nologo all
RMAKE_W2K=$(MAKECMD) /nologo all KHBUILD_W2K=1

!else
RMAKE=$(MAKECMD) /nologo etag
RMAKE_W2K=echo Skipping W2K target for ETAGS run.
!endif
!else
RMAKE=$(MAKECMD) /nologo test
RMAKE_W2K=$(MAKECMD) /nologo test KHBUILD_W2K=1
!endif
!else
RMAKE=$(MAKECMD) /nologo clean
RMAKE_W2K=$(MAKECMD) /nologo clean KHBUILD_W2K=1
!endif

start:

config: start
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

include: config
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

util: include
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

kherr: util
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

kconfig: kherr
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

kmq: kconfig
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

kcreddb: kmq
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

kmm: kcreddb
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

help: kmm
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

uilib: help
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(RMAKE_W2K)
	$(CD) ..
	$(ECHO) -- Done with $@

nidmgrdll: uilib
	$(ECHO) -- Entering $@
	$(CD) $@
	$(RMAKE)
	$(RMAKE_W2K)
	$(CD) ..
	$(ECHO) -- Done with $@

ui: nidmgrdll
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(RMAKE_W2K)
	$(CD) ..
	$(ECHO) -- Done with $@

# Now build the plugins
plugincommon: ui
	$(ECHO) -- Entering $@
	$(CD) plugins\common
	$(RMAKE)
	$(CD) ..\..
	$(ECHO) -- Done with $@

krb5plugin: plugincommon
	$(ECHO) -- Entering $@
	$(CD) plugins\krb5
	$(RMAKE)
	$(CD) ..\..
	$(ECHO) -- Done with $@

!ifndef NO_KRB4
finale: krb4plugin

krb4plugin: plugincommon
	$(ECHO) -- Entering $@
	$(CD) plugins\krb4
	$(RMAKE)
	$(CD) ..\..
	$(ECHO) -- Done with $@
!endif

!ifdef BUILD_AFS
finale: afsplugin

afsplugin: plugincommon
	$(ECHO) -- Entering $@
	$(CD) plugins\afs
	$(RMAKE)
	$(CD) ..\..
	$(ECHO) -- Done with $@
!endif

!ifdef NODOCBUILD
doctarget=
!else
doctarget=doc
!endif

finale: krb5plugin $(doctarget)
	$(ECHO) -- Done.

pdoc:

doc: pdoc
	$(ECHO) -- Entering $@:
	$(CD) $@
	$(RMAKE)
	$(CD) ..
	$(ECHO) -- Done with $@

clean::
	$(MAKECMD) /nologo CLEANRUN=1

test::
	$(MAKECMD) /nologo TESTRUN=1

etags::
	$(RM) $(TAGFILE)
	$(MAKECMD) /nologo ETAGRUN=1

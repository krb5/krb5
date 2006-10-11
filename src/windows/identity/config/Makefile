#
# Copyright (c) 2004,2005,2006 Massachusetts Institute of Technology
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


MODULE=config
!include <Makefile.w32>

all: showvars showvers mkalldirs mkversion

showvars:
	$(ECHO) SRC= $(SRC)
	$(ECHO) DESTDIR = $(DESTDIR)
	$(ECHO) OBJDIR = $(OBJDIR)
	$(ECHO).
	$(ECHO) CC = $(CC)
	$(ECHO) DOXYGEN = $(DOXYGEN)
	$(ECHO) HHC = $(HHC)

showvers:
	$(ECHO) ---- Version Information ----
	$(ECHO) NETIDMGR_VERSION=    $(NETIDMGR_VERSION)
	$(ECHO) NETIDMGR_VERSION_API=$(NETIDMGR_VERSION_API)
	$(ECHO) NETIDMGR_RELEASEDESC=$(NETIDMGR_RELEASEDESC)
	$(ECHO) Build Type          :$(KH_BUILD), $(KH_RELEASE)
	$(ECHO) Strings:
	$(ECHO) Company    = $(NETIDMGR_SRC_COMPANY_1033)
	$(ECHO) Copyright  = $(NETIDMGR_SRC_COPYRIGHT_1033)
	$(ECHO) ---- End Version Information ---
	$(ECHO).

mkalldirs:
!	if !exist($(DESTROOT))
	-$(MKDIR) $(DESTROOT)
!	endif
!	if !exist($(OBJROOT))
	-$(MKDIR) $(OBJROOT)
!	endif
!	if !exist($(DESTDIR))
	-$(MKDIR) $(DESTDIR)
!	endif
!	if !exist($(OBJDIR))
	-$(MKDIR) $(OBJDIR)
!	endif
!	if !exist($(INCDIR))
	-$(MKDIR) $(INCDIR)
!	endif
!	if !exist($(BINDIR))
	-$(MKDIR) $(BINDIR)
!	endif
!	if !exist($(LIBDIR))
	-$(MKDIR) $(LIBDIR)
!	endif
!	if !exist($(DOCDIR))
	-$(MKDIR) $(DOCDIR)
!	endif
!	if !exist($(OBJDIR)\W2K)
	-$(MKDIR) $(OBJDIR)\W2K
!	endif
!	if !exist($(BINDIR)\W2K)
	-$(MKDIR) $(BINDIR)\W2K
!	endif
!	if !exist($(LIBDIR)\W2K)
	-$(MKDIR) $(LIBDIR)\W2K
!	endif
	$(ECHO) Done creating directories.

VERSIONINT=$(INCDIR)\netidmgr_intver.h

VERSIONEXT=$(INCDIR)\netidmgr_version.h

# Version related defines

! if "$(KH_BUILD)"=="RETAIL"
kh_fileflags=0
! else
kh_fileflags=VS_FF_DEBUG
! endif
! if "$(KH_RELEASE)"=="PRERELEASE"
kh_fileflags=$(kh_fileflags) | VS_FF_PRERELEASE
! elseif "$(KH_RELEASE)"=="PRIVATE"
kh_fileflags=$(kh_fileflags) | VS_FF_PRIVATEBUILD
! elseif "$(KH_RELEASE)"=="SPECIAL"
kh_fileflags=$(kh_fileflags) | VS_FF_SPECIALBUILD
! endif

kh_fileos=VOS_NT_WINDOWS32
kh_filetype_app=VFT_APP
kh_filetype_dll=VFT_DLL

mkversion: $(VERSIONINT) $(VERSIONEXT)

# Version and build strings

!if "$(KH_RELEASE)" == "OFFICIAL"
NETIDMGR_VERSION_STR_1033=$(NETIDMGR_VERSION)
NETIDMGR_COMMENT_STR_1033=Official build.  Please send bug reports to kfw-bugs@MIT.EDU
!elseif "$(KH_RELEASE)" == "PRERELEASE"
NETIDMGR_VERSION_STR_1033=$(NETIDMGR_VERSION) Prelease $(NETIDMGR_RELEASEDESC)
NETIDMGR_COMMENT_STR_1033=Prerelease build.  Please send bug reports to kfw-bugs@MIT.EDU
!elseif "$(KH_RELEASE)" == "PRIVATE"
NETIDMGR_VERSION_STR_1033=$(NETIDMGR_VERSION).PRIVATE
NETIDMGR_PRIVATE_STR_1033=Private build.  Please send bug reports to kfw-bugs@MIT.EDU
!elseif "$(KH_RELEASE)" == "SPECIAL"
NETIDMGR_VERSION_STR_1033=$(NETIDMGR_VERSION).SPECIAL
NETIDMGR_SPECIAL_STR_1033=Special build.  Please send bug reports to kfw-bugs@MIT.EDU
!endif

!if "$(KH_BUILD)" == "DEBUG"
NETIDMGR_VERSION_STR_1033=$(NETIDMGR_VERSION_STR_1033).DEBUG
!else
!endif

NETIDMGR_PRODUCT_1033=NetIDMgr $(NETIDMGR_VERSION_STR_1033)

!include netidmgr_version.h.in

!include netidmgr_intver.h.in

clean::
!	if exist($(VERSIONINT))
	$(RM) $(VERSIONINT)
!	endif
!	if exist($(VERSIONEXT))
	$(RM) $(VERSIONEXT)
!	endif


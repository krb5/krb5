#
# Copyright (c) 2004 Massachusetts Institute of Technology
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


MODULE=nidmgrdll
!include <../config/Makefile.w32>

!if  ("$(CPU)" == "IA64" ) || ("$(CPU)" == "AMD64" ) || ("$(CPU)" == "ALPHA64" )
DLLFILE=$(BINDIR)\nidmgr64.dll
LIBFILE=$(LIBDIR)\nidmgr64.lib
!else
DLLFILE=$(BINDIR)\nidmgr32.dll
LIBFILE=$(LIBDIR)\nidmgr32.lib
!endif

UTILDIR=$(OBJDIR)\util

KHERRDIR=$(OBJDIR)\kherr

KCONFIGDIR=$(OBJDIR)\kconfig

KMQDIR=$(OBJDIR)\kmq

KCDBDIR=$(OBJDIR)\kcreddb

KMMDIR=$(OBJDIR)\kmm

UIDIR=$(OBJDIR)\uilib

OBJFILES= \
	$(OBJ)\dllmain.obj		\
	$(UTILDIR)\hashtable.obj	\
	$(UTILDIR)\sync.obj		\
	$(UTILDIR)\mstring.obj		\
	$(UTILDIR)\perfstat.obj		\
	$(KHERRDIR)\kherrmain.obj	\
	$(KHERRDIR)\kherr.obj		\
	$(KCONFIGDIR)\kconfigmain.obj	\
	$(KCONFIGDIR)\api.obj		\
	$(KMQDIR)\kmqmain.obj		\
	$(KMQDIR)\init.obj		\
	$(KMQDIR)\msgtype.obj		\
	$(KMQDIR)\consumer.obj 		\
	$(KMQDIR)\publisher.obj 	\
	$(KMQDIR)\kmqconfig.obj		\
	$(KCDBDIR)\buf.obj 		\
	$(KCDBDIR)\attrib.obj 		\
	$(KCDBDIR)\credential.obj 	\
	$(KCDBDIR)\credset.obj 		\
	$(KCDBDIR)\credtype.obj 	\
	$(KCDBDIR)\identity.obj 	\
	$(KCDBDIR)\init.obj 		\
	$(KCDBDIR)\kcreddbmain.obj 	\
	$(KCDBDIR)\type.obj 		\
	$(KCDBDIR)\kcdbconfig.obj	\
	$(KMMDIR)\kmmmain.obj 		\
	$(KMMDIR)\kmm.obj 		\
	$(KMMDIR)\kmm_plugin.obj 	\
	$(KMMDIR)\kmm_module.obj 	\
	$(KMMDIR)\kmm_reg.obj 		\
	$(KMMDIR)\kmm_registrar.obj 	\
	$(KMMDIR)\kmmconfig.obj		\
	$(UIDIR)\rescache.obj 		\
	$(UIDIR)\action.obj 		\
	$(UIDIR)\creddlg.obj		\
	$(UIDIR)\alert.obj 		\
	$(UIDIR)\propsheet.obj 		\
	$(UIDIR)\propwnd.obj 		\
	$(UIDIR)\uilibmain.obj 		\
	$(UIDIR)\actiondef.obj 		\
	$(UIDIR)\acceldef.obj		\
	$(UIDIR)\configui.obj		\
	$(UIDIR)\trackerwnd.obj		\
	$(UIDIR)\uibind.obj		\
	$(UIDIR)\version.obj

RESFILES= \
	$(OBJ)\nidmgrdll.res		\
	$(KCDBDIR)\kcredres.res		\
	$(KMMDIR)\kmm_msgs.res		\

SDKLIBFILES= \
	advapi32.lib			\
	strsafe.lib			\
	comctl32.lib			\
	shlwapi.lib			\
	version.lib

!if  ("$(CPU)" == "IA64" ) || ("$(CPU)" == "AMD64" ) || ("$(CPU)" == "ALPHA64" )
SCLIB=bufferoverflowu.lib
!else
SCLIB=
!endif

$(DLLFILE): $(OBJFILES) $(RESFILES)
	$(DLLGUILINK) $(LIBFILES) $(SDKLIBFILES) $(SCLIB)
	$(_VC_MANIFEST_EMBED_DLL)
	$(_VC_MANIFEST_CLEAN)

all: mkdirs $(DLLFILE)

clean::
	if exist '$(DLLFILE)' $(RM) $(DLLFILE)
	if exist '$(DLLFILE).manifest' $(RM) $(DLLFILE).manifest

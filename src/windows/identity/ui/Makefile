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


MODULE=ui
!include <../config/Makefile.w32>

EXEFILE=$(BINDIR)\netidmgr.exe

MANIFESTFILE=$(BINDIR)\netidmgr.exe.static.manifest

OBJFILES= 			\
	$(OBJ)\main.obj 	\
	$(OBJ)\mainmenu.obj 	\
	$(OBJ)\toolbar.obj 	\
	$(OBJ)\statusbar.obj 	\
	$(OBJ)\notifier.obj 	\
	$(OBJ)\timer.obj	\
	$(OBJ)\uiconfig.obj 	\
	$(OBJ)\mainwnd.obj 	\
	$(OBJ)\credwnd.obj 	\
	$(OBJ)\htwnd.obj 	\
	$(OBJ)\passwnd.obj 	\
	$(OBJ)\newcredwnd.obj 	\
	$(OBJ)\propertywnd.obj 	\
	$(OBJ)\credfuncs.obj 	\
	$(OBJ)\configwnd.obj	\
	$(OBJ)\aboutwnd.obj	\
	$(OBJ)\reqdaemon.obj	\
	$(OBJ)\addrchange.obj	\
	$(OBJ)\debugfuncs.obj	\
	$(OBJ)\taskbar.obj	\
	$(OBJ)\cfg_general_wnd.obj \
	$(OBJ)\cfg_identities_wnd.obj \
	$(OBJ)\cfg_notif_wnd.obj \
	$(OBJ)\cfg_plugins_wnd.obj \
	$(OBJ)\cfg_appear_wnd.obj

RESFILES= \
	$(OBJ)\khapp.res	\
	$(OBJ)\appver.res

!if  ("$(CPU)" == "IA64" ) || ("$(CPU)" == "AMD64" ) || ("$(CPU)" == "ALPHA64" )
LIBFILES=$(LIBDIR)\nidmgr64.lib
!else
LIBFILES=$(LIBDIR)\nidmgr32.lib
!endif

SDKLIBFILES= 			\
	comctl32.lib 		\
	shell32.lib		\
	htmlhelp.lib		\
	iphlpapi.lib		\
	shlwapi.lib		\
	msimg32.lib		\
	ole32.lib

$(OBJ)\uiconfig.c: uiconfig.csv $(CONFDIR)\csvschema.cfg
	$(CCSV) $** $@

$(OBJ)\khapp.res: lang\en_us\khapp.rc
	$(RC2RES)

$(OBJ)\appver.res: appver.rc
	$(RC2RES)

!if "$(KH_BUILD)"=="RETAIL"
$(MANIFESTFILE): netidmgr.manifest.$(CPU).$(KH_CLVER)
!else
$(MANIFESTFILE): netidmgr.manifest.$(CPU).$(KH_CLVER).debug
!endif
	$(CP) $** $@

!if  ("$(CPU)" == "IA64" ) || ("$(CPU)" == "AMD64" ) || ("$(CPU)" == "ALPHA64" )
SCLIB=bufferoverflowu.lib
!else
SCLIB=
!endif

$(EXEFILE): $(OBJFILES) $(RESFILES) $(LIBFILES)
	$(EXEGUILINK) $(SDKLIBFILES) $(SCLIB)
	$(_VC_MANIFEST_EMBED_EXE) $(MANIFESTFILE)
	$(_VC_MANIFEST_CLEAN)

all: mkdirs $(MANIFESTFILE) $(EXEFILE)

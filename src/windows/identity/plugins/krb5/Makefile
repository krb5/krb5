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


MODULE=plugins\krb5
!include <../../config/Makefile.w32>

DLLFILE=$(BINDIR)\krb5cred.dll

LIBFILE=$(LIBDIR)\krb5cred.lib

OBJFILES= \
	$(LIBDIR)\dynimport.obj 	\
	$(LIBDIR)\krb5common.obj 	\
	$(OBJ)\krb5main.obj 		\
	$(OBJ)\datarep.obj 		\
	$(OBJ)\errorfuncs.obj 		\
	$(OBJ)\krb5plugin.obj 		\
	$(OBJ)\krb5props.obj 		\
	$(OBJ)\krb5newcreds.obj 	\
	$(OBJ)\krb5funcs.obj 		\
	$(OBJ)\krb5config.obj		\
	$(OBJ)\krb5identpro.obj		\
	$(OBJ)\krb5configdlg.obj	\
	$(OBJ)\krb5configcc.obj		\
	$(OBJ)\krb5configid.obj		\
	$(OBJ)\krb5configids.obj



SDKLIBFILES=	\
	netapi32.lib	\
	shlwapi.lib	\
	comctl32.lib

!if  ("$(CPU)" == "IA64" ) || ("$(CPU)" == "AMD64" ) || ("$(CPU)" == "ALPHA64" )
SCLIB=bufferoverflowu.lib
LIBFILES= \
	$(LIBDIR)\nidmgr64.lib		\
	$(KFWLIBDIR)\loadfuncs.lib
!else
SCLIB=
LIBFILES= \
	$(LIBDIR)\nidmgr32.lib		\
	$(KFWLIBDIR)\loadfuncs.lib
!endif

MSGRESFILE=$(OBJ)\krb5_msgs.res

VERRESFILE=$(OBJ)\version.res

$(OBJ)\krb5config.c: krbconfig.csv $(CONFDIR)\csvschema.cfg
	$(CCSV) $** $@

$(DLLFILE):  $(OBJFILES) $(VERRESFILE) 
	$(DLLGUILINK) $(MSGRESFILE) $(LIBFILES) $(SDKLIBFILES) $(SCLIB)
	$(_VC_MANIFEST_EMBED_DLL)
	$(_VC_MANIFEST_CLEAN)

$(MSGRESFILE): $(OBJ)\krb5_msgs.rc

$(OBJ)\krb5_msgs.rc: lang\krb5_msgs.mc
	$(MC2RC)

all: mkdirs $(MSGRESFILE) $(DLLFILE) lang

lang::

# Repeat this block as necessary redefining LANG for additional
# languages.

# Begin language block
LANG=en_us

LANGDLL=$(BINDIR)\krb5cred_$(LANG).dll

lang:: $(LANGDLL)

$(LANGDLL): $(OBJ)\langres_$(LANG).res $(OBJ)\langres_ver_$(LANG).res
	$(DLLRESLINK)

$(OBJ)\langres_$(LANG).res: lang\$(LANG)\langres.rc
	$(RC2RES)

$(OBJ)\langres_ver_$(LANG).res: version.rc
	$(RC) $(RFLAGS) $(rincflags) /d LANGVER /d LANG_$(LANG) /fo $@ $** 
# End language block

clean::
!if defined(INCFILES)
	$(RM) $(INCFILES)
!endif

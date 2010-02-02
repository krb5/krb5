#
# Copyright (c) 2004 Massachusetts Institute of Technology
# Copyright (c) 2007 Secure Endpoints Inc.
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


MODULE=plugins\krb4
!include <../../config/Makefile.w32>

DLLFILE=$(BINDIR)\krb4cred.dll

LIBFILE=$(LIBDIR)\krb4cred.lib

OBJFILES= 				\
	$(LIBDIR)\dynimport.obj 	\
	$(LIBDIR)\krb5common.obj 	\
	$(OBJ)\krb4main.obj 		\
	$(OBJ)\krb4plugin.obj 		\
	$(OBJ)\krb4funcs.obj 		\
	$(OBJ)\errorfuncs.obj 		\
	$(OBJ)\krb4config.obj 		\
	$(OBJ)\krb4configdlg.obj	\
	$(OBJ)\krb4newcreds.obj



SDKLIBFILES=

!if  ("$(CPU)" == "IA64" ) || ("$(CPU)" == "AMD64" ) || ("$(CPU)" == "ALPHA64" )
SCLIB=bufferoverflowu.lib
LIBFILES= 				\
	$(LIBDIR)\nidmgr64.lib		\
	$(KFWLIBDIR)\loadfuncs.lib
!else
SCLIB=
LIBFILES= 				\
	$(LIBDIR)\nidmgr32.lib		\
	$(KFWLIBDIR)\loadfuncs.lib
!endif

VERRESFILE=$(OBJ)\version.res

MSGRESFILE=$(OBJ)\krb4_msgs.res

$(MSGRESFILE): $(OBJ)\krb4_msgs.rc

$(OBJ)\krb4_msgs.rc: lang\krb4_msgs.mc
	$(MC2RC)

$(OBJ)\krb4config.c: krbconfig.csv $(CONFDIR)\csvschema.cfg
	$(CCSV) $** $@

$(DLLFILE): $(OBJFILES) $(VERRESFILE) $(MSGRESFILE)
	$(DLLGUILINK) $(LIBFILES) $(SDKLIBFILES) $(SCLIB)
	$(_VC_MANIFEST_EMBED_DLL)
	$(_VC_MANIFEST_CLEAN)

all: mkdirs $(MSGRESFILE) $(DLLFILE) lang

lang::

# Repeat this block as necessary redefining LANG for additional
# languages.

# Begin language block
LANG=en_us

LANGDLL=$(BINDIR)\krb4cred_$(LANG).dll

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



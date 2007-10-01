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


MODULE=kcreddb
!include <../config/Makefile.w32>

INCFILES= \
	$(INCDIR)\kcreddb.h

OBJFILES= \
	$(OBJ)\buf.obj \
	$(OBJ)\attrib.obj \
	$(OBJ)\credential.obj \
	$(OBJ)\credset.obj \
	$(OBJ)\credtype.obj \
	$(OBJ)\identity.obj \
	$(OBJ)\init.obj \
	$(OBJ)\kcreddbmain.obj \
	$(OBJ)\type.obj \
	$(OBJ)\kcdbconfig.obj

$(OBJ)\kcdbconfig.c: kcdbconfig.csv $(CONFDIR)\csvschema.cfg
	$(CCSV) $** $@

$(OBJ)\kcredres.res: lang\en_us\kcredres.rc
	$(RC2RES)

all: mkdirs $(INCFILES) $(OBJ)\kcredres.res $(OBJFILES)

clean::
	if exist ..\obj $(RM) $(INCFILES)

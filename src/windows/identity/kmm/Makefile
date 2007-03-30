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


MODULE=kmm
!include <../config/Makefile.w32>

INCFILES= \
	$(INCDIR)\kmm.h \
	$(INCDIR)\kplugin.h

OBJFILES= \
	$(OBJ)\kmmmain.obj \
	$(OBJ)\kmm.obj \
	$(OBJ)\kmm_plugin.obj \
	$(OBJ)\kmm_module.obj \
	$(OBJ)\kmm_reg.obj \
	$(OBJ)\kmm_registrar.obj \
	$(OBJ)\kmmconfig.obj

MSGRESFILE=$(OBJ)\kmm_msgs.res

$(OBJ)\kmmconfig.c: kmmconfig.csv $(CONFDIR)\csvschema.cfg
	$(CCSV) $** $@

$(MSGRESFILE): $(OBJ)\kmm_msgs.rc

$(OBJ)\kmm_msgs.rc: lang\kmm_msgs.mc
	$(MC2RC)

all: mkdirs $(INCFILES) $(MSGRESFILE) $(OBJFILES)

clean::
	if exist '..\obj' $(RM) $(INCFILES)
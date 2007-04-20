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


MODULE=uilib
!include <../config/Makefile.w32>

UIDLLOBJFILES=			\
	$(OBJ)\rescache.obj 	\
	$(OBJ)\action.obj 	\
	$(OBJ)\creddlg.obj	\
	$(OBJ)\alert.obj 	\
	$(OBJ)\propsheet.obj 	\
	$(OBJ)\propwnd.obj 	\
	$(OBJ)\uilibmain.obj 	\
	$(OBJ)\actiondef.obj 	\
	$(OBJ)\acceldef.obj	\
	$(OBJ)\configui.obj	\
	$(OBJ)\trackerwnd.obj	\
	$(OBJ)\uibind.obj	\
	$(OBJ)\version.obj

INCFILES=			\
	$(INCDIR)\khuidefs.h	\
	$(INCDIR)\khrescache.h 	\
	$(INCDIR)\khaction.h 	\
	$(INCDIR)\khactiondef.h	\
	$(INCDIR)\khalerts.h	\
	$(INCDIR)\khhtlink.h	\
	$(INCDIR)\khnewcred.h	\
	$(INCDIR)\khprops.h	\
	$(INCDIR)\khconfigui.h	\
	$(INCDIR)\khtracker.h	\
	$(INCDIR)\khremote.h	\
	$(INCDIR)\intaction.h	\
	$(INCDIR)\intalert.h

$(OBJ)\actiondef.c: actions.csv actiondef.cfg
	$(CCSV) $** $@

$(OBJ)\acceldef.c: accel.csv acceldef.cfg
	$(CCSV) $** $@

all: mkdirs $(INCFILES) $(UIDLLOBJFILES)


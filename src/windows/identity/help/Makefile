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


MODULE=help
!include <..\config\Makefile.w32>

CHMFILE=$(BINDIR)\netidmgr.chm

INCFILES=$(INCDIR)\khhelp.h

all: mkdirs $(CHMFILE) $(INCFILES)

$(CHMFILE): netidmgr.hhp
	-$(HHC) netidmgr.hhp
	$(CP) netidmgr.chm $(CHMFILE)

clean::
	if exist ..\obj $(RM) $(INCFILES)
	if exist netidmgr.chm $(RM) netidmgr.chm

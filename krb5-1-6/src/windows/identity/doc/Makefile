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


MODULE=doc
!include <../config/Makefile.w32>

all: mkdirs docs

docs:
	$(DOXYGEN) <<
@INCLUDE = doxyfile.cfg

PROJECT_NUMBER = "$(KHIMAIRA_VERSION)"

OUTPUT_DIRECTORY = "$(DOCDIR)"

STRIP_FROM_PATH = "$(SRC)"

INTERNAL_DOCS = NO

WARN_LOGFILE = "$(OBJ)\doxywarnings.txt"

INPUT =  "$(SRC)\include"
INPUT += "$(SRC)\kconfig"
INPUT += "$(SRC)\kcreddb"
INPUT += "$(SRC)\kmq"
INPUT += "$(SRC)\ui"
INPUT += "$(SRC)\uilib"
INPUT += "$(SRC)\util"
INPUT += "$(SRC)\doc"
INPUT += "$(SRC)\kmm"
INPUT += "$(SRC)\kherr"
!ifdef BUILD_AFS
INPUT += "$(SRC)\plugins\afs"

ALIASES =  "apiversion=$(NETIDMGR_VERSION_API)"
!endif

IMAGE_PATH = "$(SRC)\doc\images"

INCLUDE_PATH = "$(INCDIR)" "$(SRC)\include"

CHM_FILE = "$(DOCDIR)\netiddev.chm"
<<
	-$(HHC) $(DOCDIR)\html\index.hhp

clean::
	if exist "$(DOCDIR)/html" $(RMDIR) /s /q "$(DOCDIR)\html"
	if exist "$(DOCDIR)" $(RM) "$(DOCDIR)\*.*"

.SUFFIXES: .tex .dvi .ps

STYLES=changebar.sty fixunder.sty functions.sty
LIBTEX= library.tex intro.tex tables.tex errors.tex krb5.tex ccache.tex \
	rcache.tex keytab.tex libos.tex library.ind

DESTEX= libdes.tex

all: library.ps libdes.ps


libdes.dvi: $(DESTEX) $(STYLES)

library.ps: library.dvi

# hard to capture two-pass semantics in Makefiles...
# library.ind: library.dvi
library.ind: library.idx
	index library.idx

library.dvi:  $(LIBTEX) $(STYLES)

.tex.dvi:
	latex $*


.dvi.ps:
	dvips $*.dvi -o


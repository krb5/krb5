.SUFFIXES: .tex .dvi .ps

STYLES=changebar.sty fixunder.sty functions.sty
LIBTEX= library.tex krb5.tex ccache.tex rcache.tex keytab.tex libos.tex \
	kdb.tex encrypt.tex cksum.tex crc-32.tex library.ind

DESTEX= libdes.tex

all: library.ps libdes.ps


libdes.ps: libdes.dvi
libdes.tex: $(DESTEX) $(STYLES)

library.ps: library.dvi

# hard to capture two-pass semantics in Makefiles...
# library.ind: library.dvi
library.ind:
	index library.idx

library.tex: $(LIBTEX) $(STYLES)

.tex.dvi:
	latex $*


.dvi.ps:
	dvi2ps -r $*.dvi >$*.ps


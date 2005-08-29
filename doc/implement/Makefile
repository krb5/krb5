.SUFFIXES: .tex .dvi .ps

STYLES= fixunder.sty functions.sty
LIBTEX= implement.tex ccache-i.tex rcache-i.tex keytab-i.tex libos-i.tex \
	kdb-i.tex encrypt-i.tex cksum-i.tex crc-32-i.tex implement.ind


all: implement.ps


implement.ps: implement.dvi

# hard to capture two-pass semantics in Makefiles...
# implement.ind: implement.dvi
implement.ind: implement.idx
	makeindex implement.idx

implement.idx: 
	touch implement.ind
	latex implement.tex
	rm implement.ind

clean:
	rm -f *.toc *.log *.idx *.ind *.aux *.ilg

really-clean: clean
	rm -f *.dvi *.ps


implement.dvi:  $(LIBTEX) $(STYLES)

.tex.dvi:
	latex $*


.dvi.ps:
	dvips $*.dvi -o


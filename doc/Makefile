.SUFFIXES: .texi .dvi .ps .info

all:: install.info  install.dvi

.texi.dvi:
	texi2dvi $*.texi


.texi.info:
	makeinfo $*.texi


clean:: 
	rm -f *.log *.info *.dvi *.aux *.toc *.cp *.fn *.vr *.tp *.ky \
		*.pg *.ps *.info-?

SRCDIR=../src
DVI=texi2dvi
DVIPS=dvips -o "$@"
PSPDF=ps2pdf
INFO=makeinfo
HTML=makeinfo --html --no-split
RM=rm -f
TAR=tar -chvf
GZIP=gzip -9
MANPS=./man2ps
MANTXT=nroff -man 
PERL=perl
MANHTML=$(PERL) man2html



MANPAGES=$(SRCDIR)/clients/kdestroy/kdestroy.M $(SRCDIR)/clients/kinit/kinit.M $(SRCDIR)/clients/klist/klist.M $(SRCDIR)/clients/ksu/ksu.M $(SRCDIR)/clients/kpasswd/kpasswd.M

.PHONY: all
all:: clean-temp-ps clean-tex

.PHONY: clean
clean:: clean-all

.PHONY: clean-all
clean-all:: clean-tex clean-backup clean-final clean-tarfiles

.PHONY: clean-final
clean-final::
	$(RM) *.ps *.info *.info-? *.html *.pdf

.PHONY: clean-tex
clean-tex::
	$(RM) *.aux *.cp *.dvi *.fn *.ky *.log *.pg *.toc *.tp *.vr *.fns *.vrs *.tps

.PHONY: clean-backup
clean-backup::
	$(RM) *~ #*

.PHONY: clean-tarfiles
clean-tarfiles::
	$(RM) *.tar *.tar.gz *.tgz

.PHONY: clean-temp-ps
clean-temp-ps::
	$(RM) ftp?.ps kinit?.ps klist?.ps kdestroy?.ps ksu?.ps rlogin?.ps \
		rcp?.ps rsh?.ps telnet?.ps kpasswd?.ps

.PHONY: tgz
tgz::
	$(TAR) krb5-docs.tar copyright.texinfo definitions.texinfo texinfo.tex *-guide.ps *.info *.info-? *.html
	$(GZIP) krb5-docs.tar
	$(MV) krb5-docs.tar.gz krb5-docs.tgz

../NOTICE: notice.texinfo definitions.texinfo copyright.texinfo
	makeinfo --plaintext -o $@ notice.texinfo

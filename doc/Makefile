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

USER_GUIDE_INCLUDES=definitions.texinfo copyright.texinfo glossary.texinfo
USER_GUIDE_DEPS=user-guide.texinfo $(USER_GUIDE_INCLUDES)

.PHONY: all
all:: user-guide-full clean-temp-ps clean-tex

.PHONY: user-guide-full
user-guide-full:: user-guide user-guide-info user-guide-html

.PHONY: user-guide
user-guide:: user-guide.ps user-guide.pdf

user-guide.ps: $(USER_GUIDE_DEPS)
	$(DVI) user-guide.texinfo
	$(MANPS) $(MANPAGES)
	$(DVIPS) user-guide

user-guide.pdf: user-guide.ps
	$(PSPDF) user-guide.ps user-guide.pdf

.PHONY: user-guide-info
user-guide-info:: krb5-user.info

krb5-user.info: $(USER_GUIDE_DEPS)
	$(INFO) user-guide.texinfo

.PHONY: user-guide-html
user-guide-html:: user-guide.html

user-guide.html: $(USER_GUIDE_DEPS)
	$(MANTXT) $(SRCDIR)/clients/kdestroy/kdestroy.M | $(MANHTML) > kdestroy.html
	$(MANTXT) $(SRCDIR)/clients/kinit/kinit.M | $(MANHTML) > kinit.html
	$(MANTXT) $(SRCDIR)/clients/klist/klist.M | $(MANHTML) > klist.html
	$(MANTXT) $(SRCDIR)/clients/ksu/ksu.M | $(MANHTML) > ksu.html
	$(MANTXT) $(SRCDIR)/clients/kpasswd/kpasswd.M | $(MANHTML) > kpasswd.html
	$(HTML) user-guide.texinfo		

.PHONY: implementor.ps implementor.pdf implementor.info
implementor.pdf: implementor.ps
	$(PSPDF) implementor.ps
implementor.ps: implementor.texinfo
	$(DVI) implementor.texinfo
	$(DVIPS) implementor
implementor.info: implementor.texinfo
	$(INFO) implementor.texinfo

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
	$(TAR) krb5-docs.tar copyright.texinfo definitions.texinfo glossary.texinfo  texinfo.tex user-guide.texinfo *-guide.ps *.info *.info-? *.html
	$(GZIP) krb5-docs.tar
	$(MV) krb5-docs.tar.gz krb5-docs.tgz

../NOTICE: notice.texinfo definitions.texinfo copyright.texinfo
	makeinfo --plaintext -o $@ notice.texinfo

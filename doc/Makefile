SRCDIR=../src
DVI=texi2dvi
DVIPS=dvips -o "$@.ps"
INFO=makeinfo
HTML=texi2html
RM=rm -f
TAR=tar -chvf
GZIP=gzip -9
MANPS=./man2ps
all:: admin-guide-full install-guide-full user-guide-full tgz

admin-guide-full:: admin-guide admin-guide-info admin-guide-html

admin-guide::
	$(DVI) admin.texinfo
	$(DVIPS) admin

admin-guide-html::
	$(HTML) admin.texinfo

admin-guide-info::
	$(INFO) admin.texinfo

install-guide-full:: install-guide install-guide-info install-guide-html

install-guide::
	$(DVI) cyg-install.texinfo
	$(DVIPS) install

install-guide-html::
	$(HTML) cyg-install.texinfo		

install-guide-info::
	$(INFO) cyg-install.texinfo

user-guide-full:: user-guide user-guide-info user-guide-html

user-guide::
	$(DVI) user-guide.texinfo
	$(MANPS) $(SRCDIR)/appl/gssftp/ftp/ftp.M $(SRCDIR)/clients/kdestroy/kdestroy.M $(SRCDIR)/clients/kinit/kinit.M $(SRCDIR)/clients/klist/klist.M $(SRCDIR)/clients/ksu/ksu.M $(SRCDIR)/appl/bsd/rcp.M $(SRCDIR)/appl/bsd/rlogin.M $(SRCDIR)/appl/bsd/rsh.M $(SRCDIR)/appl/telnet/telnet/telnet.1
	$(DVIPS) user-guide

user-guide-info::
	$(INFO) user-guide.texinfo

user-guide-html::
	$(HTML) user-guide.texinfo		

clean:: clean-all

clean-all:: clean-tex clean-backup clean-final clean-tarfiles

clean-final::
	$(RM) *.ps *.info *.info-? *.html

clean-tex::
	$(RM) *.aux *.cp *.dvi *.fn *.ky *.log *.pg *.toc *.tp *.vr

clean-backup::
	$(RM) *~ #*

clean-tarfiles::
	$(RM) *.tar *.tar.gz *.tgz

tgz::
	$(TAR) krb5-docs.tar admin.texinfo build.texinfo copyright.texinfo definitions.texinfo document-list.texinfo glossary.texinfo cyg-install.texinfo texinfo.tex user-guide.texinfo *-guide.ps *.info *.info-? *.html
	$(GZIP) krb5-docs.tar
	$(MV) krb5-docs.tar.gz krb5-docs.tgz

SRCDIR=../src
DVI=texi2dvi
DVIPS=dvips -o "$@"
INFO=makeinfo
HTML=makeinfo --html
RM=rm -f
TAR=tar -chvf
GZIP=gzip -9
MANPS=./man2ps
MANTXT=nroff -man 
MANHTML=./man2html

ADMIN_INCLUDES=definitions.texinfo copyright.texinfo document-list.texinfo \
	glossary.texinfo support-enc.texinfo salts.texinfo krb5conf.texinfo \
	kdcconf.texinfo dnstxt.texinfo dnssrv.texinfo send-pr.texinfo
ADMIN_DEPS=admin.texinfo $(ADMIN_INCLUDES)

INSTALL_INCLUDES=definitions.texinfo copyright.texinfo document-list.texinfo \
	dnstxt.texinfo dnssrv.texinfo build.texinfo bug-report.texinfo \
	krb5conf.texinfo kdcconf.texinfo send-pr.texinfo
INSTALL_DEPS=install.texinfo $(INSTALL_INCLUDES)

MANPAGES=$(SRCDIR)/appl/gssftp/ftp/ftp.M $(SRCDIR)/clients/kdestroy/kdestroy.M $(SRCDIR)/clients/kinit/kinit.M $(SRCDIR)/clients/klist/klist.M $(SRCDIR)/clients/ksu/ksu.M $(SRCDIR)/appl/bsd/rcp.M $(SRCDIR)/appl/bsd/rlogin.M $(SRCDIR)/appl/bsd/rsh.M $(SRCDIR)/appl/telnet/telnet/telnet.1 $(SRCDIR)/kadmin/passwd/kpasswd.M

USER_GUIDE_INCLUDES=definitions.texinfo copyright.texinfo glossary.texinfo
USER_GUIDE_DEPS=user-guide.texinfo $(USER_GUIDE_INCLUDES)

KRB425_INCLUDES=definitions.texinfo copyright.texinfo
KRB425_DEPS=krb425.texinfo $(KRB425_INCLUDES)

.PHONY: all
all:: admin-guide-full install-guide-full user-guide-full krb425-guide-full clean-temp-ps clean-tex

.PHONY: admin-guide-full
admin-guide-full:: admin-guide admin-guide-info admin-guide-html

.PHONY: admin-guide
admin-guide:: admin-guide.ps

admin-guide.ps: $(ADMIN_DEPS)
	$(DVI) admin.texinfo
	$(DVIPS) admin

.PHONY: admin-guide-html
admin-guide-html:: admin.html

admin.html: $(ADMIN_DEPS)
	$(HTML) admin.texinfo

.PHONY: admin-guide-info
admin-guide-info:: krb5-admin.info

krb5-admin.info: $(ADMIN_DEPS)
	$(INFO) admin.texinfo

.PHONY: install-guide-full
install-guide-full:: install-guide install-guide-info install-guide-html

.PHONY: install-guide
install-guide:: install-guide.ps

install-guide.ps: $(INSTALL_DEPS)
	$(DVI) install.texinfo
	$(DVIPS) install

.PHONY: install-guide-html
install-guide-html:: install.html

install.html:: $(INSTALL_DEPS)
	$(HTML) install.texinfo		

.PHONY: install-guide-info
install-guide-info:: krb5-install.info

krb5-install.info: $(INSTALL_DEPS)
	$(INFO) install.texinfo

.PHONY: user-guide-full
user-guide-full:: user-guide user-guide-info user-guide-html

.PHONY: user-guide
user-guide:: user-guide.ps

user-guide.ps: $(USER_GUIDE_DEPS)
	$(DVI) user-guide.texinfo
	$(MANPS) $(MANPAGES)
	$(DVIPS) user-guide

.PHONY: user-guide-info
user-guide-info:: krb5-user.info

krb5-user.info: $(USER_GUIDE_DEPS)
	$(INFO) user-guide.texinfo

.PHONY: user-guide-html
user-guide-html:: user-guide.html

user-guide.html: $(USER_GUIDE_DEPS)
	$(MANTXT) $(SRCDIR)/appl/gssftp/ftp/ftp.M | $(MANHTML) > ftp.html
	$(MANTXT) $(SRCDIR)/clients/kdestroy/kdestroy.M | $(MANHTML) > kdestroy.html
	$(MANTXT) $(SRCDIR)/clients/kinit/kinit.M | $(MANHTML) > kinit.html
	$(MANTXT) $(SRCDIR)/clients/klist/klist.M | $(MANHTML) > klist.html
	$(MANTXT) $(SRCDIR)/clients/ksu/ksu.M | $(MANHTML) > ksu.html
	$(MANTXT) $(SRCDIR)/appl/bsd/rcp.M | $(MANHTML) > rcp.html
	$(MANTXT) $(SRCDIR)/appl/bsd/rlogin.M | $(MANHTML) > rlogin.html
	$(MANTXT) $(SRCDIR)/appl/bsd/rsh.M | $(MANHTML) > rsh.html
	$(MANTXT) $(SRCDIR)/appl/telnet/telnet/telnet.1 | $(MANHTML) > telnet.html
	$(MANTXT) $(SRCDIR)/kadmin/passwd/kpasswd.M | $(MANHTML) > kpasswd.html
	$(HTML) user-guide.texinfo		

.PHONY: krb425-guide-full
krb425-guide-full:: krb425-guide krb425-guide-info krb425-guide-html

.PHONY: krb425-guide
krb425-guide:: krb425-guide.ps

krb425-guide.ps: $(KRB425_DEPS)
	$(DVI) krb425.texinfo
	$(DVIPS) krb425

.PHONY: krb425-guide-html
krb425-guide-html:: krb425.html

krb425.html:: $(KRB425_DEPS)
	$(HTML) krb425.texinfo		

.PHONY: krb425-guide-info
krb425-guide-info:: krb425.info

krb425.info: $(KRB425_DEPS)
	$(INFO) krb425.texinfo

.PHONY: clean
clean:: clean-all

.PHONY: clean-all
clean-all:: clean-tex clean-backup clean-final clean-tarfiles

.PHONY: clean-final
clean-final::
	$(RM) *.ps *.info *.info-? *.html

.PHONY: clean-tex
clean-tex::
	$(RM) *.aux *.cp *.dvi *.fn *.ky *.log *.pg *.toc *.tp *.vr

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
	$(TAR) krb5-docs.tar admin.texinfo build.texinfo copyright.texinfo definitions.texinfo document-list.texinfo glossary.texinfo install.texinfo texinfo.tex user-guide.texinfo *-guide.ps *.info *.info-? *.html
	$(GZIP) krb5-docs.tar
	$(MV) krb5-docs.tar.gz krb5-docs.tgz

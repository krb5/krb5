## config/pre.in
## common prefix for all Makefile.in in the Kerberos V5 tree.

WHAT = unix

# Directory syntax:
R=/
C=./
S=/
U=../

BUILDTOP = .
srcdir = .

CPPFLAGS = 
DEFS =  -DHAVE_LIBNSL=1  $(CPPFLAGS)
CC = gcc
LD = $(PURE) gcc
CCOPTS = 
LIBS =  -lnsl
KRB5ROOT= /krb5
KRB4=/usr/kerberos
INSTALL=@INSTALL@
INSTALL_PROGRAM=@INSTALL_PROGRAM@ -s
INSTALL_DATA=@INSTALL_DATA@
INSTALL_SETUID=$(INSTALL) -s -m 4755

KRB5MANROOT = $(KRB5ROOT)/man
ADMIN_BINDIR = $(KRB5ROOT)/admin
SERVER_BINDIR = $(KRB5ROOT)/sbin
CLIENT_BINDIR = $(KRB5ROOT)/bin
ADMIN_MANDIR = $(KRB5MANROOT)/man8
SERVER_MANDIR = $(KRB5MANROOT)/man8
CLIENT_MANDIR = $(KRB5MANROOT)/man1
FILE_MANDIR = $(KRB5MANROOT)/man5
KRB5_LIBDIR = $(KRB5ROOT)/lib
KRB5_INCDIR = $(KRB5ROOT)/include
KRB5_INCSUBDIRS = \
	$(KRB5_INCDIR)/krb5 \
	$(KRB5_INCDIR)/asn.1 \
	$(KRB5_INCDIR)/kerberosIV


RM = rm -f
CP  = cp
MV = mv -f
CHMOD=chmod
RANLIB = @RANLIB@
ARCHIVE = @ARCHIVE@
ARADD = @ARADD@
LN = @LN_S@
AWK = @AWK@
LEX = @LEX@
LEXLIB = @LEXLIB@
YACC = @YACC@

SRCTOP = $(srcdir)/$(BUILDTOP)
SUBDIRS = util include  lib kdc admin kadmin slave clients appl tests

TOPLIBD = $(BUILDTOP)/lib

OBJEXT = o
LIBEXT = a
EXEEXT =

all::
# Generated automatically from Makefile.in by configure.
CFLAGS = $(CCOPTS) $(DEFS)

##DOSBUILDTOP = .
##DOS!include $(BUILDTOP)\config\windows.in

prefix = /usr/local
exec_prefix = $(prefix)
binprefix =
manprefix =

bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
mandir = $(prefix)/man/man1
manext = 1

SRCS =  
HDRS = 

DISTFILES = $(SRCS) $(HDRS) COPYING COPYING.LIB ChangeLog Makefile.in

all:: all-$(WHAT)

all-unix::

all-mac::

all-: all-windows

all-windows:: makefile-windows
	@echo Making in include
	cd include
	-$(MAKE) -$(MAKEFLAGS)
	@echo Making in util\et
	cd ..\util\et
	-$(MAKE) -$(MAKEFLAGS)
	@echo Making in lib
	cd ..\..\lib
	-$(MAKE) -$(MAKEFLAGS)
	@echo Making in windows
	cd ..\windows
	-$(MAKE) -$(MAKEFLAGS)
	cd ..

world::
	date
	make $(MFLAGS) mastermakefiles
	make $(MFLAGS) depend
	make $(MFLAGS) all
	date

INSTALLMKDIRS = $(KRB5ROOT) $(KRB5MANROOT) $(KRB5OTHERMKDIRS) \
		$(ADMIN_BINDIR) $(SERVER_BINDIR) $(CLIENT_BINDIR) \
		$(ADMIN_MANDIR) $(SERVER_MANDIR) $(CLIENT_MANDIR) \
		$(FILE_MANDIR) $(KRB5_LIBDIR) $(KRB5_INCDIR) \
		$(KRB5_INCSUBDIRS)

install:: install-mkdirs

depend:: includes


install-mkdirs:
	@for i in $(INSTALLMKDIRS); do \
		if test -d $(DESTDIR)$$i; then :; else (set -x; mkdir $(DESTDIR)$$i); fi \
	done

# install::
#	$(MAKE) $(MFLAGS) install.man

# rebuild the Makefiles in the master source tree
mastermakefiles::
	-$(MV) Makefile Makefile.bak
	$(MAKE) -f Makefile.bak Makefile
	$(MAKE) Makefiles

.c.o:
	$(CC) -c $(CPPFLAGS) $(DEFS) -I$(srcdir) $(CFLAGS) $<

TAGS: $(SRCS)
	etags $(SRCS)

clean:: clean-$(WHAT)

clean-:: clean-unix
clean-mac:: clean-unix
clean-unix::
	$(RM) *.o core

mostlyclean: clean

distclean: clean
	rm -f Makefile config.status

realclean: distclean
	rm -f TAGS

dist: $(DISTFILES)
	echo cpio-`sed -e '/version_string/!d' \
	-e 's/[^0-9.]*\([0-9.]*\).*/\1/' -e q version.c` > .fname
	rm -rf `cat .fname`
	mkdir `cat .fname`
	-ln $(DISTFILES) `cat .fname`
	for file in $(DISTFILES); do \
	  test -r `cat .fname`/$$file || cp -p $$file `cat .fname`; \
	done
	tar chzf `cat .fname`.tar.gz `cat .fname`
	rm -rf `cat .fname` .fname

# Macintosh build process...

# Build all things for the Mac build, which need to be built on 
# Unix first.
unixmac:
	(cd lib/krb5/error_tables; make -f Makefile.in unixmac)
	(cd lib/gssapi/generic; make -f Makefile.in unixmac)


# Microsoft Windows build process...

#
# Windows configuration
#
makefile-windows:: wconfig.c config\pre.in config\post.in makefile.in \
		include\makefile.in include\krb5\makefile.in \
		lib\makefile.in lib\crypto\makefile.in \
		lib\crypto\crc32\makefile.in lib\crypto\des\makefile.in \
		lib\crypto\md4\makefile.in lib\crypto\md5\makefile.in \
		lib\crypto\os\makefile.in lib\des425\makefile.in \
		lib\gssapi\makefile.in lib\gssapi\generic\makefile.in \
		lib\gssapi\krb5\makefile.in lib\krb5\makefile.in \
		lib\krb5\asn.1\makefile.in lib\krb5\ccache\makefile.in \
		lib\krb5\ccache\file\makefile.in \
		lib\krb5\ccache\stdio\makefile.in \
		lib\krb5\error_ta\makefile.in \
		lib\krb5\free\makefile.in lib\krb5\keytab\makefile.in \
		lib\krb5\keytab\file\makefile.in lib\krb5\krb\makefile.in \
		lib\krb5\os\makefile.in lib\krb5\posix\makefile.in \
		lib\krb5\rcache\makefile.in \
		util\et\makefile.in
	SET CL=/nologo
	$(CC) /AL wconfig.c
	copy Makefile Makefile.bak
	.\wconfig config <makefile.in >makefile
	.\wconfig config <include\makefile.in >include\makefile
	.\wconfig config <include\krb5\makefile.in >include\krb5\makefile
	.\wconfig config <lib\makefile.in >lib\makefile
	.\wconfig config <lib\crypto\makefile.in >lib\crypto\makefile
	.\wconfig config <lib\crypto\crc32\makefile.in >lib\crypto\crc32\makefile
	.\wconfig config <lib\crypto\des\makefile.in >lib\crypto\des\makefile
	.\wconfig config <lib\crypto\md4\makefile.in >lib\crypto\md4\makefile
	.\wconfig config <lib\crypto\md5\makefile.in >lib\crypto\md5\makefile
	.\wconfig config <lib\crypto\os\makefile.in >lib\crypto\os\makefile
	.\wconfig config <lib\des425\makefile.in >lib\des425\makefile
	.\wconfig config <lib\gssapi\makefile.in >lib\gssapi\makefile
	.\wconfig config <lib\gssapi\generic\makefile.in >lib\gssapi\generic\makefile
	.\wconfig config <lib\gssapi\krb5\makefile.in >lib\gssapi\krb5\makefile
	.\wconfig config <lib\krb5\makefile.in >lib\krb5\makefile
	.\wconfig config <lib\krb5\asn.1\makefile.in >lib\krb5\asn.1\makefile
	.\wconfig config <lib\krb5\ccache\makefile.in >lib\krb5\ccache\makefile
	.\wconfig config <lib\krb5\ccache\file\makefile.in >lib\krb5\ccache\file\makefile
	.\wconfig config <lib\krb5\ccache\stdio\makefile.in >lib\krb5\ccache\stdio\makefile
	.\wconfig config <lib\krb5\error_ta\makefile.in >lib\krb5\error_ta\makefile
	.\wconfig config <lib\krb5\free\makefile.in >lib\krb5\free\makefile
	.\wconfig config <lib\krb5\keytab\makefile.in >lib\krb5\keytab\makefile
	.\wconfig config <lib\krb5\keytab\file\makefile.in >lib\krb5\keytab\file\makefile
	.\wconfig config <lib\krb5\krb\makefile.in >lib\krb5\krb\makefile
	.\wconfig config <lib\krb5\os\makefile.in >lib\krb5\os\makefile
	.\wconfig config <lib\krb5\posix\makefile.in >lib\krb5\posix\makefile
	.\wconfig config <lib\krb5\rcache\makefile.in >lib\krb5\rcache\makefile
	.\wconfig config <util\et\makefile.in >util\et\makefile
	config\rm.bat wconfig.obj wconfig.exe msvc.pdb

clean-windows::
	@echo Making clean in include
	cd include
	-$(MAKE) -$(MAKEFLAGS) clean
	@echo Making clean in util\et
	cd ..\util\et
	-$(MAKE) -$(MAKEFLAGS) clean
	@echo Making clean in lib
	cd ..\..\lib
	-$(MAKE) -$(MAKEFLAGS) clean
	@echo Making clean in windows
	cd ..\windows
	-$(MAKE) -$(MAKEFLAGS) clean
	cd ..
	@echo Making clean locally
	config\rm.bat *.obj msvc.pdb *.err wconfig.obj wconfig.exe

#
# Builds the zip file that distributes Kerberos sources for DOS sites
# from the source tree on Unix.	
#
ZIPFILES= ./* \
	config/* include/* include/krb5/* include/krb5/asn.1/* \
	include/krb5/stock/* include/sys/* lib/* lib/crypto/* \
	lib/crypto/crc32/* lib/crypto/des/* lib/crypto/md4/* \
	lib/crypto/md5/* lib/crypto/os/* lib/des425/* lib/gssapi/* \
	lib/gssapi/generic/* lib/gssapi/krb5/* lib/krb425/* \
	lib/krb5/* lib/krb5/asn.1/* lib/krb5/krb/* \
	lib/krb5/ccache/* lib/krb5/ccache/file/* \
	lib/krb5/ccache/stdio/* lib/krb5/error_tables/* \
	lib/krb5/free/* lib/krb5/keytab/* lib/krb5/keytab/file/* \
	lib/krb5/os/* lib/krb5/posix/* lib/krb5/rcache/* util/et/* \
	windows/* windows/cns/* windows/wintel/*

ZIPBINARYFILES=windows/cns/*.ico windows/wintel/*.ico

ZIPEXCLUDE= LIB/KRB5.SAB \
	INCLUDE/KRB5/AUTOCONF.H \
	LIB/CRYPTO/MD4/T_MDDRIV LIB/CRYPTO/MD5/T_MDDRIV \
	WINDOWS/CNS/*.ICO WINDOWS/WINTEL/*.ICO \
	*.O *.A

kerbsrc.zip: awk-windows
	rm -f kerbsrc.zip
	zip -Dlk kerbsrc.zip $(ZIPFILES) -x $(ZIPEXCLUDE)
	zip -Dk kerbsrc.zip $(ZIPBINARYFILES)
#
# Part of building the PC release has to be done on Unix. This includes
# anything the requires awk.
#
AH  = util/et/et_h.awk
AC  = util/et/et_c.awk
INC = include/krb5/
ET  = lib/krb5/error_tables/
GG  = lib/gssapi/generic/
GK  = lib/gssapi/krb5/

awk-windows:
	gawk -f $(AH) outfile=$(INC)asn1_err.h $(ET)asn1_err.et
	gawk -f $(AH) outfile=$(INC)kdb5_err.h $(ET)kdb5_err.et
	gawk -f $(AH) outfile=$(INC)krb5_err.h $(ET)krb5_err.et
	gawk -f $(AH) outfile=$(INC)kv5m_err.h $(ET)kv5m_err.et
	gawk -f $(AH) outfile=$(INC)adm_err.h $(ET)adm_err.et
	gawk -f $(AC) outfile=$(ET)asn1_err.c $(ET)asn1_err.et
	gawk -f $(AC) outfile=$(ET)kdb5_err.c $(ET)kdb5_err.et
	gawk -f $(AC) outfile=$(ET)krb5_err.c $(ET)krb5_err.et
	gawk -f $(AC) outfile=$(ET)kv5m_err.c $(ET)kv5m_err.et
	gawk -f $(AC) outfile=$(ET)adm_err.c $(ET)adm_err.et
	gawk -f $(AH) outfile=$(GG)gssapi_err_generic.h $(GG)gssapi_err_generic.et
	gawk -f $(AC) outfile=$(GG)gssapi_err_generic.c $(GG)gssapi_err_generic.et
	gawk -f $(AH) outfile=$(GK)gssapi_err_krb5.h $(GK)gssapi_err_krb5.et
	gawk -f $(AC) outfile=$(GK)gssapi_err_krb5.c $(GK)gssapi_err_krb5.et

# config/post.in
# put all:: first just in case no other rules occur here
#
all::

check::

clean:: clean-$(WHAT)
	$(RM) config.log pre.out post.out Makefile.out

clean-unix::
	if test -n "$(OBJS)" ; then $(RM) $(OBJS); else :; fi

clean-windows::
	$(RM) *.$(OBJEXT)
	$(RM) msvc.pdb *.err
# [DIVERSION_MAKEFILE] contents

SHELL=/bin/sh

Makefile: $(srcdir)/Makefile.in config.status $(SRCTOP)/config/pre.in $(SRCTOP)/config/post.in
	$(SHELL) config.status
config.status: $(srcdir)/configure
	$(SHELL) config.status --recheck
$(srcdir)/configure: $(srcdir)/configure.in $(SRCTOP)/aclocal.m4
	cd $(srcdir); autoconf --localdir=$(BUILDTOP) --macrodir=$(BUILDTOP)/util/autoconf


all::
	@case '${MFLAGS}' in *[ik]*) set +e ;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo "making" "in $(CURRENT_DIR)$$i..."; \
			$(MAKE) $(MFLAGS) CC="$(CC)" CCOPTS="$(CCOPTS)" \
			CURRENT_DIR=$(CURRENT_DIR)$$i/ all); \
	done

clean::
	@case '${MFLAGS}' in *[ik]*) set +e ;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo "cleaning" "in $(CURRENT_DIR)$$i..."; \
			$(MAKE) $(MFLAGS) CC="$(CC)" CCOPTS="$(CCOPTS)" \
			CURRENT_DIR=$(CURRENT_DIR)$$i/ clean); \
	done

install::
	@case '${MFLAGS}' in *[ik]*) set +e ;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo "installing" "in $(CURRENT_DIR)$$i..."; \
			$(MAKE) $(MFLAGS) CC="$(CC)" CCOPTS="$(CCOPTS)" \
			CURRENT_DIR=$(CURRENT_DIR)$$i/ install); \
	done

check::
	@case '${MFLAGS}' in *[ik]*) set +e ;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo "checking" "in $(CURRENT_DIR)$$i..."; \
			$(MAKE) $(MFLAGS) CC="$(CC)" CCOPTS="$(CCOPTS)" \
			CURRENT_DIR=$(CURRENT_DIR)$$i/ check); \
	done


############################################################
## config/pre.in
## common prefix for all Makefile.in in the Kerberos V5 tree.
##

WHAT = unix
SHELL=/bin/sh

all:: all-$(WHAT)

clean:: clean-$(WHAT)

distclean:: distclean-$(WHAT)

install:: install-$(WHAT)

check:: check-$(WHAT)

install-headers:: install-headers-$(WHAT)

##############################
# Recursion rule support
#

# The commands for the recursion targets live in config/post.in.
#
# General form of recursion rules:
#
# Each recursive target foo-unix has related targets: foo-prerecurse,
# foo-recurse, and foo-postrecurse
#
# The foo-recurse rule is in post.in.  It is what actually recursively
# calls make.
#
# foo-recurse depends on foo-prerecurse, so any targets that must be
# built before descending into subdirectories must be dependencies of
# foo-prerecurse.
#
# foo-postrecurse depends on foo-recurse, but targets that must be
# built after descending into subdirectories should be have
# foo-recurse as dependencies in addition to being listed under
# foo-postrecurse, to avoid ordering issues.
#
# The foo-prerecurse, foo-recurse, and foo-postrecurse rules are all
# single-colon rules, to avoid nasty ordering problems with
# double-colon rules.
#
# e.g.
# all:: includes foo
# foo:
#	echo foo
# includes::
#	echo bar
# includes::
#	echo baz
#
# will result in "bar", "foo", "baz" on AIX, and possibly others.
all-unix:: all-postrecurse
all-postrecurse: all-recurse
all-recurse: all-prerecurse

all-prerecurse:
all-postrecurse:

clean-unix:: clean-postrecurse
clean-postrecurse: clean-recurse
clean-recurse: clean-prerecurse

clean-prerecurse:
clean-postrecurse:

distclean-unix: distclean-postrecurse
distclean-postrecurse: distclean-recurse
distclean-recurse: distclean-prerecurse

distclean-prerecurse:
distclean-postrecurse:

install-unix:: install-postrecurse
install-postrecurse: install-recurse
install-recurse: install-prerecurse

install-prerecurse:
install-postrecurse:

install-headers-unix:: install-headers-postrecurse
install-headers-postrecurse: install-headers-recurse
install-headers-recurse: install-headers-prerecurse

install-headers-prerecurse:
install-headers-postrecurse:

check-unix:: check-postrecurse
check-postrecurse: check-recurse
check-recurse: check-prerecurse

check-prerecurse:
check-postrecurse:

Makefiles: Makefiles-postrecurse
Makefiles-postrecurse: Makefiles-recurse
Makefiles-recurse: Makefiles-prerecurse

Makefiles-prerecurse:
Makefiles-postrecurse:

#
# end recursion rule support
##############################

# Directory syntax:
#
# begin relative path
REL=
# this is magic... should only be used for preceding a program invocation
C=./
# "/" for UNIX, "\" for Windows; *sigh*
S=/

SUBDIRS =  $(LOCAL_SUBDIRS)
srcdir = .
SRCTOP = ./$(BUILDTOP)

CONFIG_RELTOPDIR = ../..

ALL_CFLAGS = $(DEFS) $(DEFINES) $(LOCALINCLUDES) $(CPPFLAGS) $(CFLAGS)
CFLAGS = -g
CPPFLAGS = -I$(BUILDTOP)/include -I$(SRCTOP)/include -I$(BUILDTOP)/include/krb5 -I$(SRCTOP)/include/krb5 -I/usr/athena/include  -DKRB5_KRB4_COMPAT -DKRB5_PRIVATE=1
DEFS = -DHAVE_CONFIG_H
CC = /usr/gcc/bin/gcc
LD = $(PURE) /usr/gcc/bin/gcc
DEPLIBS = @DEPLIBS@
LDFLAGS = -L/usr/athena/lib 
LD_UNRESOLVED_PREFIX = @LD_UNRESOLVED_PREFIX@
LD_SHLIBDIR_PREFIX = @LD_SHLIBDIR_PREFIX@
LDARGS = @LDARGS@
LIBS = -lsocket -lnsl  -lresolv
SRVLIBS = @SRVLIBS@
SRVDEPLIBS = @SRVDEPLIBS@
CLNTLIBS = @CLNTLIBS@
CLNTDEPLIBS = @CLNTDEPLIBS@

INSTALL=/usr/athena/bin/install -c
INSTALL_STRIP=
INSTALL_PROGRAM=${INSTALL} $(INSTALL_STRIP)
INSTALL_DATA=${INSTALL} -m 644
INSTALL_SHLIB=$(INSTALL_DATA)
INSTALL_SETUID=$(INSTALL) $(INSTALL_STRIP) -m 4755 -o root
## This is needed because autoconf will sometimes define ${prefix} to be
## ${prefix}.
prefix=/usr/local
INSTALL_PREFIX=$(prefix)
INSTALL_EXEC_PREFIX=${prefix}
exec_prefix=${prefix}
SHLIB_TAIL_COMP=@SHLIB_TAIL_COMP@

KRB5MANROOT = ${prefix}/man
ADMIN_BINDIR = ${exec_prefix}/sbin
SERVER_BINDIR = ${exec_prefix}/sbin
CLIENT_BINDIR =${exec_prefix}/bin
ADMIN_MANDIR = $(KRB5MANROOT)/man8
SERVER_MANDIR = $(KRB5MANROOT)/man8
CLIENT_MANDIR = $(KRB5MANROOT)/man1
FILE_MANDIR = $(KRB5MANROOT)/man5
KRB5_LIBDIR = ${exec_prefix}/lib
KRB5_SHLIBDIR = ${exec_prefix}/lib$(SHLIB_TAIL_COMP)
KRB5_INCDIR = ${prefix}/include
KRB5_INCSUBDIRS = \
	$(KRB5_INCDIR)/gssapi \
	$(KRB5_INCDIR)/kerberosIV

#
# Macros used by the KADM5 (OV-based) unit test system.
# XXX check which of these are actually used!
#
TESTDIR		= $(BUILDTOP)/kadmin/testing
STESTDIR	= $(SRCTOP)/kadmin/testing
COMPARE_DUMP	= $(TESTDIR)/scripts/compare_dump.pl
FIX_CONF_FILES	= $(TESTDIR)/scripts/fixup-conf-files.pl
INITDB		= $(STESTDIR)/scripts/init_db
MAKE_KEYTAB	= $(TESTDIR)/scripts/make-host-keytab.pl
LOCAL_MAKE_KEYTAB= $(TESTDIR)/scripts/make-host-keytab.pl
RESTORE_FILES	= $(STESTDIR)/scripts/restore_files.sh
SAVE_FILES	= $(STESTDIR)/scripts/save_files.sh
ENV_SETUP	= $(TESTDIR)/scripts/env-setup.sh
CLNTTCL		= $(TESTDIR)/util/ovsec_kadm_clnt_tcl
SRVTCL		= $(TESTDIR)/util/ovsec_kadm_srv_tcl
# Dejagnu variables.
# We have to set the host with --host so that setup_xfail will work.
# If we don't set it, then the host type used is "native", which
# doesn't match "*-*-*".
host=sparc-sun-solaris2.8
DEJAFLAGS	= $(DEJALFLAGS) $(CLFLAGS) --debug --srcdir $(srcdir) --host \
		   $(host)
RUNTEST		= runtest $(DEJAFLAGS)

START_SERVERS	= $(STESTDIR)/scripts/start_servers $(TEST_SERVER) $(TEST_PATH)
START_SERVERS_LOCAL = $(STESTDIR)/scripts/start_servers_local

STOP_SERVERS	= $(STESTDIR)/scripts/stop_servers $(TEST_SERVER) $(TEST_PATH)
STOP_SERVERS_LOCAL = $(STESTDIR)/scripts/stop_servers_local
#
# End of macros for the KADM5 unit test system.
#

transform = s,x,x,

RM = rm -f
CP  = cp
MV = mv -f
CHMOD=chmod
RANLIB = ranlib
ARCHIVE = @ARCHIVE@
ARADD = @ARADD@
LN = ln -s
AWK = @AWK@
LEX = @LEX@
LEXLIB = @LEXLIB@
YACC = @YACC@
AUTOCONF = autoconf
AUTOCONFFLAGS = 
AUTOCONFINCFLAGS = --localdir
AUTOHEADER = autoheader
AUTOHEADERFLAGS = 

HOST_TYPE = @HOST_TYPE@
SHEXT = @SHEXT@
STEXT=@STEXT@
VEXT=@VEXT@
DO_MAKE_SHLIB = @DO_MAKE_SHLIB@
SHLIB_STATIC_TARGET=@SHLIB_STATIC_TARGET@

TOPLIBD = $(BUILDTOP)/lib

OBJEXT = o
LIBEXT = a
EXEEXT =

#
# variables for libraries, for use in linking programs
# -- this may want to get broken out into a separate frag later
#
#
# Note: the following variables must be set in any Makefile.in that
# uses KRB5_BUILD_PROGRAM
#
# PROG_LIBPATH	list of dirs, in -Ldir form, to search for libraries at link
# PROG_RPATH	list of dirs, in dir1:dir2 form, for rpath purposes
#
# invocation is like:
# prog: foo.o bar.o $(KRB5_BASE_DEPLIBS)
# 	$(CC_LINK) -o $@ foo.o bar.o $(KRB5_BASE_LIBS)


CC_LINK=$(PURE) $(CC) $(PROG_LIBPATH) $(LDFLAGS)

# prefix (with no spaces after) for rpath flag to cc
RPATH_FLAG=-R

# this gets set by configure to either $(STLIBEXT) or $(SHLIBEXT),
# depending on whether we're building with shared libraries.
DEPLIBEXT=.a

KADMCLNT_DEPLIB	= $(TOPLIBD)/libkadm5clnt$(DEPLIBEXT)
KADMSRV_DEPLIB	= $(TOPLIBD)/libkadm5srv$(DEPLIBEXT)
KDB5_DEPLIB	= $(TOPLIBD)/libkdb5$(DEPLIBEXT)
DB_DEPLIB	= $(DB_DEPLIB-k5)
DB_DEPLIB-k5	= $(TOPLIBD)/libdb$(DEPLIBEXT)
DB_DEPLIB-sys	=
GSSRPC_DEPLIB	= $(TOPLIBD)/libgssrpc$(DEPLIBEXT)
GSS_DEPLIB	= $(TOPLIBD)/libgssapi_krb5$(DEPLIBEXT)
KRB4_DEPLIB	= $(TOPLIBD)/libkrb4$(DEPLIBEXT)		# $(TOPLIBD)/libkrb4$(DEPLIBEXT)
DES425_DEPLIB	= $(TOPLIBD)/libdes425$(DEPLIBEXT)	# $(TOPLIBD)/libdes425$(DEPLIBEXT)
KRB5_DEPLIB	= $(TOPLIBD)/libkrb5$(DEPLIBEXT)
CRYPTO_DEPLIB	= $(TOPLIBD)/libk5crypto$(DEPLIBEXT)
COM_ERR_DEPLIB	= $(COM_ERR_DEPLIB-k5)
COM_ERR_DEPLIB-sys = # empty
COM_ERR_DEPLIB-k5 = $(TOPLIBD)/libcom_err$(DEPLIBEXT)

# These are forced to use ".a" as an extension because they're never
# built shared.
SS_DEPLIB	= $(SS_DEPLIB-k5)
SS_DEPLIB-k5	= $(TOPLIBD)/libss.a
SS_DEPLIB-sys	=
KRB524_DEPLIB	= $(BUILDTOP)/krb524/libkrb524.a
PTY_DEPLIB	= $(TOPLIBD)/libpty.a

KRB5_BASE_DEPLIBS	= $(KRB5_DEPLIB) $(CRYPTO_DEPLIB) $(COM_ERR_DEPLIB)
KRB4COMPAT_DEPLIBS	= $(KRB4_DEPLIB) $(DES425_DEPLIB) $(KRB5_BASE_DEPLIBS)
KDB5_DEPLIBS		= $(KDB5_DEPLIB) $(DB_DEPLIB)
GSS_DEPLIBS		= $(GSS_DEPLIB)
GSSRPC_DEPLIBS		= $(GSSRPC_DEPLIB) $(GSS_DEPLIBS)
KADM_COMM_DEPLIBS	= $(GSSRPC_DEPLIBS) $(KDB5_DEPLIBS) $(GSSRPC_DEPLIBS)
KADMSRV_DEPLIBS		= $(KADMSRV_DEPLIB) $(KDB5_DEPLIBS) $(KADM_COMM_DEPLIBS)
KADMCLNT_DEPLIBS	= $(KADMCLNT_DEPLIB) $(KADM_COMM_DEPLIBS)

# Header file dependencies we might override.
# See util/depfix.sed.
# Also see depend-verify-* in post.in, which wants to confirm that we're using
# the in-tree versions.
COM_ERR_VERSION = k5
COM_ERR_DEPS	= $(COM_ERR_DEPS-k5)
COM_ERR_DEPS-sys =
COM_ERR_DEPS-k5	= $(BUILDTOP)/include/com_err.h
SS_VERSION	= k5
SS_DEPS		= $(SS_DEPS-k5)
SS_DEPS-sys	=
SS_DEPS-k5	= $(BUILDTOP)/include/ss/ss.h $(BUILDTOP)/include/ss/ss_err.h
DB_VERSION	= k5
DB_DEPS		= $(DB_DEPS-k5)
DB_DEPS-sys	=
DB_DEPS-k5	= $(BUILDTOP)/include/db.h $(BUILDTOP)/include/db-config.h
DB_DEPS-redirect = $(BUILDTOP)/include/db.h

# Header file dependencies that might depend on whether krb4 support
# is compiled.

KRB_ERR_H_DEP	= $(BUILDTOP)/include/kerberosIV/krb_err.h
KRB524_H_DEP	= $(BUILDTOP)/include/krb524.h
KRB524_ERR_H_DEP= $(BUILDTOP)/include/krb524_err.h

# LIBS gets substituted in... e.g. -lnsl -lsocket

# GEN_LIB is -lgen if needed for regexp
GEN_LIB		= 

SS_LIB		= $(SS_LIB-k5)
SS_LIB-sys	= 
SS_LIB-k5	= $(TOPLIBD)/libss.a
KDB5_LIB	= -lkdb5
DB_LIB		= -ldb

KRB5_LIB			= -lkrb5
K5CRYPTO_LIB			= -lk5crypto
COM_ERR_LIB			= -lcom_err
GSS_KRB5_LIB			= -lgssapi_krb5

# KRB4_LIB is -lkrb4 if building --with-krb4
# needs fixing if ever used on Mac OS X!
KRB4_LIB	= -lkrb4

# DES425_LIB is -ldes425 if building --with-krb4
# needs fixing if ever used on Mac OS X!
DES425_LIB	= -ldes425

# KRB524_LIB is $(BUILDTOP)/krb524/libkrb524.a if building --with-krb4
# needs fixing if ever used on Mac OS X!
KRB524_LIB	= $(BUILDTOP)/krb524/libkrb524.a

# HESIOD_LIBS is -lhesiod...
HESIOD_LIBS	= 

KRB5_BASE_LIBS	= $(KRB5_LIB) $(K5CRYPTO_LIB) $(COM_ERR_LIB) $(GEN_LIB) $(LIBS)
KRB4COMPAT_LIBS	= $(KRB4_LIB) $(DES425_LIB) $(KRB5_BASE_LIBS)
KDB5_LIBS	= $(KDB5_LIB) $(DB_LIB)
GSS_LIBS	= $(GSS_KRB5_LIB)
# needs fixing if ever used on Mac OS X!
GSSRPC_LIBS	= -lgssrpc $(GSS_LIBS)
KADM_COMM_LIBS	= $(GSSRPC_LIBS)
# need fixing if ever used on Mac OS X!
KADMSRV_LIBS	= -lkadm5srv $(HESIOD_LIBS) $(KDB5_LIBS) $(KADM_COMM_LIBS)
KADMCLNT_LIBS	= -lkadm5clnt $(KADM_COMM_LIBS)

# need fixing if ever used on Mac OS X!
PTY_LIB		= -lpty

#
# some more stuff for --with-krb4
KRB4_LIBPATH	= 
KRB4_INCLUDES	= -I$(SRCTOP)/include/kerberosIV -I$(BUILDTOP)/include/kerberosIV

#
# variables for --with-tcl=
TCL_LIBS	= @TCL_LIBS@
TCL_LIBPATH	= @TCL_LIBPATH@
TCL_RPATH	= @TCL_RPATH@
TCL_MAYBE_RPATH = @TCL_MAYBE_RPATH@
TCL_INCLUDES	= @TCL_INCLUDES@

# error table rules
#
### /* these are invoked as $(...) foo.et, which works, but could be better */
COMPILE_ET= $(COMPILE_ET-k5)
COMPILE_ET-sys= compile_et
COMPILE_ET-k5= $(BUILDTOP)/util/et/compile_et -d $(SRCTOP)/util/et

.SUFFIXES:  .h .c .et .ct

# These versions cause both .c and .h files to be generated at once.
# But GNU make doesn't understand this, and parallel builds can trigger
# both of them at once, causing them to stomp on each other.  The versions
# below only update one of the files, so compile_et has to get run twice,
# but it won't break parallel builds.
#.et.h: ; $(COMPILE_ET) $<
#.et.c: ; $(COMPILE_ET) $<

.et.h:
	d=ettmp$$$$ ; (cp $< $$d.et && $(COMPILE_ET) $$d.et && mv $$d.h $*.h) ; \
		e=$$? ; rm -f $$d.* ; exit $$e

.et.c:
	d=ettmp$$$$ ; (cp $< $$d.et && $(COMPILE_ET) $$d.et && mv $$d.c $*.c) ; \
		e=$$? ; rm -f $$d.* ; exit $$e

# rule to make object files
#
.SUFFIXES: .c .o
.c.o:
	$(CC) $(ALL_CFLAGS) -c $<

# ss command table rules
#
MAKE_COMMANDS= $(MAKE_COMMANDS-k5)
MAKE_COMMANDS-sys= mk_cmds
MAKE_COMMANDS-k5= $(BUILDTOP)/util/ss/mk_cmds

.ct.c:
	$(MAKE_COMMANDS) $<

##
## end of pre.in
############################################################
thisconfigdir=./..
myfulldir=util/db2/test
mydir=test
BUILDTOP=$(REL)..$(S)..$(S)..

FCTSH = /usr/bin/sh
TMPDIR=.

LOCALINCLUDES=	-I. -I$(srcdir)/../include -I../include -I$(srcdir)/../mpool \
		-I$(srcdir)/../btree -I$(srcdir)/../hash -I$(srcdir)/../db

PROG_LIBPATH=-L$(TOPLIBD)
PROG_RPATH=$(KRB5_LIBDIR)

KRB5_RUN_ENV= 

all::

dbtest: dbtest.o $(DB_DEPLIB)
	$(CC_LINK) -o $@ dbtest.o $(STRERROR_OBJ) $(DB_LIB)

check:: dbtest
	$(KRB5_RUN_ENV) srcdir=$(srcdir) TMPDIR=$(TMPDIR) $(FCTSH) $(srcdir)/run.test

bttest.o: $(srcdir)/btree.tests/main.c
	$(CC) $(ALL_CFLAGS) -c $(srcdir)/btree.tests/main.c -o $@

bttest: bttest.o $(DB_DEPLIB)
	$(CC_LINK) -o $@ bttest.o $(STRERROR_OBJ) $(DB_LIB)

clean-unix::
	$(RM) dbtest.o dbtest __dbtest
	$(RM) bttest.o bttest
############################################################
## config/post.in
##

# in case there is no default target (very unlikely)
all::

check-windows::

##############################
# dependency generation
#

depend:: depend-postrecurse
depend-postrecurse: depend-recurse
depend-recurse: depend-prerecurse

depend-prerecurse:
depend-postrecurse:

depend-postrecurse: depend-update-makefile

ALL_DEP_SRCS= $(SRCS) $(EXTRADEPSRCS)

# be sure to check ALL_DEP_SRCS against *what it would be if SRCS and
# EXTRADEPSRCS are both empty*
.depend-verify-srcdir:
	@if test "$(srcdir)" = "." ; then \
		echo 1>&2 error: cannot build dependencies with srcdir=. ; \
		echo 1>&2 "(can't distinguish generated files from source files)" ; \
		exit 1 ; \
	else \
		if test -r .depend-verify-srcdir; then :; \
			else (set -x; touch .depend-verify-srcdir); fi \
	fi
.depend-verify-et: depend-verify-et-$(COM_ERR_VERSION)
depend-verify-et-k5:
	@if test -r .depend-verify-et; then :; \
		else (set -x; touch .depend-verify-et); fi
depend-verify-et-sys:
	@echo 1>&2 error: cannot build dependencies using system et package
	@exit 1
.depend-verify-ss: depend-verify-ss-$(SS_VERSION)
depend-verify-ss-k5:
	@if test -r .depend-verify-ss; then :; \
		else (set -x; touch .depend-verify-ss); fi
depend-verify-ss-sys:
	@echo 1>&2 error: cannot build dependencies using system ss package
	@exit 1
.depend-verify-db: depend-verify-db-$(DB_VERSION)
depend-verify-db-k5:
	@if test -r .depend-verify-db; then :; \
		else (set -x; touch .depend-verify-db); fi
depend-verify-db-sys:
	@echo 1>&2 error: cannot build dependencies using system db package
	@exit 1
.depend-verify-gcc: depend-verify-gcc-yes
depend-verify-gcc-yes:
	@if test -r .depend-verify-gcc; then :; \
		else (set -x; touch .depend-verify-gcc); fi
depend-verify-gcc-no:
	@echo 1>&2 error: The '"depend"' rules are written for gcc.
	@echo 1>&2 Please use gcc, or update the rules to handle your compiler.
	@exit 1

DEP_CFG_VERIFY = .depend-verify-srcdir \
	.depend-verify-et .depend-verify-ss .depend-verify-db
DEP_VERIFY = $(DEP_CFG_VERIFY) .depend-verify-gcc

.d: $(ALL_DEP_SRCS) $(DEP_CFG_VERIFY) depend-dependencies
	if test "$(ALL_DEP_SRCS)" != " " ; then \
		$(RM) .dtmp && $(MAKE) .dtmp && mv -f .dtmp .d ; \
	else \
		touch .d ; \
	fi

# These are dependencies of the depend target that do not get fed to
# the compiler.  Examples include generated header files.
depend-dependencies:

# .dtmp must *always* be out of date so that $? can be used to perform
# VPATH searches on the sources.
#
# NOTE: This will fail when using Make programs whose VPATH support is
# broken.
.dtmp: $(ALL_DEP_SRCS)
	$(CC) -M $(ALL_CFLAGS) $? > .dtmp

# Generate a script for dropping in the appropriate make variables, using
# directory-specific parameters.  General substitutions independent of local
# make variables happen in depfix.sed.
.depfix2.sed: .depend-verify-gcc Makefile $(SRCTOP)/util/depgen.sed
	x=`$(CC) -print-libgcc-file-name` ; \
	echo '$(SRCTOP)' '$(myfulldir)' '$(srcdir)' '$(BUILDTOP)' "$$x" | sed -f $(SRCTOP)/util/depgen.sed > .depfix2.tmp
	mv -f .depfix2.tmp .depfix2.sed

DEPLIBOBJNAMEFIX = sed -e 's;^\$$(OUTPRE)\([a-zA-Z0-9_\-]*\)\.\$$(OBJEXT):;\1.so \1.po &;'

# NOTE: This will also generate spurious $(OUTPRE) and $(OBJEXT)
# references in rules for non-library objects in a directory where
# library objects happen to be built.  It's mostly harmless.
.depend: .d .depfix2.sed $(SRCTOP)/util/depfix.sed
	sed -f .depfix2.sed < .d | sed -f $(SRCTOP)/util/depfix.sed | \
	(if test "x$(STLIBOBJS)" != "x"; then $(DEPLIBOBJNAMEFIX) ; else cat; fi ) \
	> .depend

depend-update-makefile: .depend depend-recurse
	if test -n "$(SRCS)" ; then \
		sed -e '/^# +++ Dependency line eater +++/,$$d' \
			< $(srcdir)/Makefile.in | cat - .depend \
			> $(srcdir)/Makefile.in.new; \
	$(SRCTOP)/config/move-if-changed $(srcdir)/Makefile.in.new $(srcdir)/Makefile.in ; \
	else :; fi

DEPTARGETS = .depend .d .dtmp .depfix2.sed .depfix2.tmp $(DEP_VERIFY)

#
# end dependency generation
##############################

clean:: clean-$(WHAT)

clean-unix::
	$(RM) $(OBJS) $(DEPTARGETS)

clean-windows::
	$(RM) *.$(OBJEXT)
	$(RM) msvc.pdb *.err

distclean:: distclean-$(WHAT)

distclean-normal-clean:
	$(MAKE) NORECURSE=true clean
distclean-prerecurse: distclean-normal-clean
distclean-nuke-configure-state:
	$(RM) config.log config.cache config.status Makefile
distclean-postrecurse: distclean-nuke-configure-state

Makefiles-prerecurse: Makefile

# thisconfigdir = relative path from this Makefile to config.status
# mydir = relative path from config.status to this Makefile
Makefile: $(srcdir)/Makefile.in $(thisconfigdir)/config.status \
		$(SRCTOP)/config/pre.in $(SRCTOP)/config/post.in
	cd $(thisconfigdir) && $(SHELL) config.status $(mydir)/Makefile
$(thisconfigdir)/config.status: $(srcdir)/$(thisconfigdir)/configure
	cd $(thisconfigdir) && $(SHELL) config.status --recheck
$(srcdir)/$(thisconfigdir)/configure: $(srcdir)/$(thisconfigdir)/configure.in \
		$(SRCTOP)/aclocal.m4
	-$(RM) -r $(srcdir)/$(thisconfigdir)/autom4te.cache
	cd $(srcdir)/$(thisconfigdir) && \
		$(AUTOCONF) ${AUTOCONFINCFLAGS}=$(CONFIG_RELTOPDIR) $(AUTOCONFFLAGS)
	-$(RM) -r $(srcdir)/$(thisconfigdir)/autom4te.cache

RECURSE_TARGETS=all-recurse clean-recurse distclean-recurse install-recurse \
	check-recurse depend-recurse Makefiles-recurse install-headers-recurse

# MY_SUBDIRS overrides any setting of SUBDIRS generated by the
# configure script that generated this Makefile.  This is needed when
# the configure script that produced this Makefile creates multiple
# Makefiles in different directories; the setting of SUBDIRS will be
# the same in each.
#
# LOCAL_SUBDIRS seems to account for the case where the configure
# script doesn't call any other subsidiary configure scripts, but
# generates multiple Makefiles.
$(RECURSE_TARGETS):
	@case "`echo 'x$(MFLAGS)'|sed -e 's/^x//' -e 's/ --.*$$//'`" \
		in *[ik]*) e="status=1" ;; *) e="exit 1";; esac; \
	if test -z "$(MY_SUBDIRS)" ; then \
		do_subdirs="$(SUBDIRS)" ; \
	else \
		do_subdirs="$(MY_SUBDIRS)" ; \
	fi; \
	status=0; \
	if test -n "$$do_subdirs" && test -z "$(NORECURSE)"; then \
	for i in $$do_subdirs ; do \
		if test -d $$i && test -r $$i/Makefile ; then \
		case $$i in .);; *) \
			target=`echo $@|sed s/-recurse//`; \
			echo "making $$target in $(CURRENT_DIR)$$i..."; \
			if (cd $$i ; $(MAKE) \
			    CURRENT_DIR=$(CURRENT_DIR)$$i/ $$target) then :; \
			else eval $$e; fi; \
			;; \
		esac; \
		else \
			echo "Skipping missing directory $(CURRENT_DIR)$$i" ; \
		fi; \
	done; \
	else :; \
	fi;\
	exit $$status

##
## end of post.in
############################################################

dnl
dnl
dnl arrange to stuff file in substitution
dnl
dnl AC_STUFF_FILE_PRE()
define(AC_STUFF_FILE_PRE,
[AC_DIVERT_PUSH(AC_DIVERSION_SED)dnl
1r $1
AC_DIVERT_POP()dnl
])dnl
dnl AC_STUFF_FILE_POST()
define(AC_STUFF_FILE_POST,
[AC_DIVERT_PUSH(AC_DIVERSION_SED)dnl
[$]r $1
AC_DIVERT_POP()dnl
])dnl
dnl
dnl Figure out the top of the source and build trees.  We depend on localdir
dnl being a relative pathname; we could make it general later, but for now 
dnl this is good enough.
dnl
AC_DEFUN(V5_SET_TOPDIR,[dnl
ac_reltopdir=AC_LOCALDIR
case "$ac_reltopdir" in 
/*)
	echo "Configure script built with absolute localdir pathname"
	exit 1
	;;
"")
	ac_reltopdir=.
	;;
esac
ac_topdir=$srcdir/$ac_reltopdir
ac_config_fragdir=$ac_reltopdir/config
ac_prepend=$ac_config_fragdir/pre.in
ac_postpend=$ac_config_fragdir/post.in
BUILDTOP=$ac_reltopdir
SRCTOP=$srcdir/$ac_reltopdir
if test -d "$srcdir/$ac_config_fragdir"; then
  AC_CONFIG_AUX_DIR($ac_config_fragdir)
else
  AC_MSG_ERROR([can not find config/ directory in $ac_reltopdir])
fi
AC_SUBST(BUILDTOP)dnl
AC_SUBST(SRCTOP)dnl
])dnl
dnl
dnl Does configure need to be run in immediate subdirectories of this
dnl directory?
dnl
dnl XXX we should remove this and replace CONFIG_DIRS with AC_CONFIG_SUBDIRS
dnl in all of the configure.in files.
dnl
define(CONFIG_DIRS,[AC_CONFIG_SUBDIRS($1)])dnl
dnl
dnl AC_PUSH_MAKEFILE():
dnl allow stuff to get tacked on to the end of the makefile
dnl
define(AC_PUSH_MAKEFILE,[dnl
cat>>append.out<<\PUSHEOF
])dnl
define(AC_POP_MAKEFILE,[dnl
PUSHEOF
])dnl
dnl
dnl Work around bug in autoconf which causes a relative path for 
dnl AC_PROG_INSTALL to be cached.
dnl
define(INSTALL_VARIABLE_HACK,[dnl
#
# Work around a bug in autoconf; unset the cache variable for the install 
# program if it is a relative path.
#
case "$ac_cv_path_install" in
../*|./*|[[a-zA-Z]]*)
	unset ac_cv_path_install
	;;
esac
])dnl
dnl
dnl append subdir rule -- MAKE_SUBDIRS("making",all)
dnl
define(_MAKE_SUBDIRS,[dnl
AC_PUSH_MAKEFILE()dnl
changequote(<<<,>>>)dnl

$2::<<<
	@case "`echo '$(MAKEFLAGS)'|sed -e 's/ --.*$$//'`" in \
		*[ik]*) e=:;; *) e="exit 1";; esac; \
	for i in $(SUBDIRS) ; do \
		if (cd $$i ; echo>>> $1 <<<"in $(CURRENT_DIR)$$i..."; \
			$(MAKE) CC="$(CC)" CCOPTS="$(CCOPTS)" \
			LDFLAGS="$(LDFLAGS)" \
			CURRENT_DIR=$(CURRENT_DIR)$$i/ >>>$3<<<) then :; \
		else $$e; fi; \
	done>>>
changequote([,])dnl
AC_POP_MAKEFILE()dnl
])dnl
define(MAKE_SUBDIRS,[dnl
_MAKE_SUBDIRS($1, $2, $2)])dnl
dnl
dnl take saved makefile stuff and put it in the Makefile
dnl
define(EXTRA_RULES,[
>>append.out
cat - append.out>> Makefile <<"SUBDIREOF"
# append.out contents
SUBDIREOF
])dnl
dnl
dnl take saved makefile stuff and put it in the argument
dnl
define(EXTRA_RULES_IN,[
>>append.out
cat - append.out >> $1 <<"SUBDIREOF"
# append.out contents
SUBDIREOF
])dnl
dnl
dnl take saved makefile stuff and put it in the argument
dnl
define(EXTRA_RULES_OUT,[
>>append.out
cat - append.out> $1 <<"SUBDIREOF"
# append.out contents
SUBDIREOF
])dnl
dnl
dnl drop in standard subdirectory rules
dnl
define(DO_SUBDIRS,[dnl
MAKE_SUBDIRS("making",all)
MAKE_SUBDIRS("cleaning",clean)
MAKE_SUBDIRS("installing",install)
MAKE_SUBDIRS("checking",check)
])dnl
dnl
dnl drop in standard rules for all configure files -- CONFIG_RULES
dnl
define(CONFIG_RULES,[dnl
V5_SET_TOPDIR dnl
INSTALL_VARIABLE_HACK dnl
WITH_CC dnl
WITH_CCOPTS dnl
WITH_LINKER dnl
WITH_LDOPTS dnl
WITH_CPPOPTS dnl
WITH_KRB4 dnl
AC_CONST dnl
WITH_NETLIB dnl
KRB_INCLUDE dnl
AC_PUSH_MAKEFILE()dnl
[
SHELL=/bin/sh

Makefile: $(srcdir)/Makefile.in config.status $(SRCTOP)/config/pre.in $(SRCTOP)/config/post.in
	$(SHELL) config.status
config.status: $(srcdir)/configure
	$(SHELL) config.status --recheck
$(srcdir)/configure: $(srcdir)/configure.in $(SRCTOP)/aclocal.m4
	cd $(srcdir); $(SRCTOP)/util/autoconf/autoconf --localdir=$(BUILDTOP) --macrodir=$(BUILDTOP)/util/autoconf
]
AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl check for sys_errlist -- DECLARE_SYS_ERRLIST
dnl
define(DECLARE_SYS_ERRLIST,[
AC_MSG_CHECKING([for sys_errlist declaration])
AC_CACHE_VAL(krb5_cv_decl_errlist,
[AC_TRY_LINK(
[#include <stdio.h>
#include <errno.h>], [1+sys_nerr;],dnl
 krb5_cv_decl_errlist=yes, krb5_cv_decl_errlist=no)])
AC_MSG_RESULT($krb5_cv_decl_errlist)
if test $krb5_cv_decl_errlist = no; then
	AC_DEFINE(NEED_SYS_ERRLIST)
fi
])dnl
dnl
dnl check for sigmask/sigprocmask -- CHECK_SIGPROCMASK
dnl
define(CHECK_SIGPROCMASK,[
AC_MSG_CHECKING([for use of sigprocmask])
AC_CACHE_VAL(krb5_cv_func_sigprocmask_use,
[AC_TRY_LINK(
[#include <signal.h>], [sigmask(1);], 
 krb5_cv_func_sigprocmask_use=no,
AC_TRY_LINK([#include <signal.h>], [sigprocmask(SIG_SETMASK,0,0);],
 krb5_cv_func_sigprocmask_use=yes, krb5_cv_func_sigprocmask_use=no))])
AC_MSG_RESULT($krb5_cv_func_sigprocmask_use)
if test $krb5_cv_func_sigprocmask_use = yes; then
 AC_DEFINE(USE_SIGPROCMASK)
fi
])dnl
dnl
define(AC_PROG_ARCHIVE, [AC_PROGRAM_CHECK(ARCHIVE, ar, ar cqv, false)])dnl
define(AC_PROG_ARCHIVE_ADD, [AC_PROGRAM_CHECK(ARADD, ar, ar cruv, false)])dnl
dnl
dnl drop in rules for building error tables -- ET_RULES
dnl
define(ET_RULES,[
AC_PROG_AWK dnl
AC_PUSH_MAKEFILE()dnl
[

### /* these are invoked as $(...) foo.et, which works, but could be better */
COMPILE_ET_H= $(AWK) -f $(SRCTOP)/util/et/et_h.awk outfile=$@
COMPILE_ET_C= $(AWK) -f $(SRCTOP)/util/et/et_c.awk outfile=$@
.SUFFIXES:  .h .c .et .ct

.et.h:
	$(AWK) -f $(SRCTOP)/util/et/et_h.awk outfile=$][*.h $<

.et.c:
	$(AWK) -f $(SRCTOP)/util/et/et_c.awk outfile=$][*.c $<

]
AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl drop in rules for building command tables -- SS_RULES
dnl
define(SS_RULES,[dnl
AC_PUSH_MAKEFILE()dnl
changequote({,})dnl
{

MAKE_COMMANDS= $(BUILDTOP)/util/ss/mk_cmds
.SUFFIXES:  .h .c .et .ct

.ct.c:
	@if [ $< != $}{*.ct ]; then \
		(set -x; cp $< $}{*.ct && $(MAKE_COMMANDS) $}{*.ct && $(RM) $}{*.ct) || exit 1; \
	else \
		(set -x; $(MAKE_COMMANDS) $}{*.ct) || exit 1; \
	fi

}
changequote([,])dnl
AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl check for <dirent.h> -- CHECK_DIRENT
dnl (may need to be more complex later)
dnl
define(CHECK_DIRENT,[
AC_HEADER_CHECK(dirent.h,AC_DEFINE(USE_DIRENT_H))])dnl
dnl
dnl check if sys/fcntl.h is needed for O_* -- CHECK_FCNTL
dnl
define(CHECK_FCNTL,[
AC_MSG_CHECKING([if O_RDONLY is needed from sys/fcntl.h])
AC_CACHE_VAL(krb5_cv_decl_fcntl_ordonly,
[AC_TRY_LINK(
[#include <sys/param.h>
#include <sys/types.h>
#include <sys/file.h>],
[1+O_RDONLY;], krb5_cv_decl_fcntl_ordonly=no,
AC_TRY_LINK([#include <sys/param.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/fcntl.h>],
[1+O_RDONLY;],krb5_cv_decl_fcntl_ordonly=yes,krb5_cv_decl_fcntl_ordonly=no))])
AC_MSG_RESULT($krb5_cv_decl_fcntl_ordonly)
if test $krb5_cv_decl_fcntl_ordonly = yes; then
  AC_DEFINE(NEED_SYS_FCNTL_H)
fi
])dnl
dnl
dnl check if union wait is defined, or if WAIT_USES_INT -- CHECK_WAIT_TYPE
dnl
define(CHECK_WAIT_TYPE,[
AC_MSG_CHECKING([for union wait])
AC_CACHE_VAL(krb5_cv_struct_wait,
[AC_TRY_COMPILE(
[#include <sys/wait.h>], [union wait i;], 
	krb5_cv_struct_wait=yes, krb5_cv_struct_wait=no)])
AC_MSG_RESULT($krb5_cv_struct_wait)
if test $krb5_cv_struct_wait = no; then
	AC_DEFINE(WAIT_USES_INT)
fi
])dnl
dnl
dnl check for POSIX signal handling -- CHECK_SIGNALS
dnl
define(CHECK_SIGNALS,[
AC_FUNC_CHECK(sigprocmask,
AC_MSG_CHECKING(for sigset_t and POSIX_SIGNALS)
AC_CACHE_VAL(krb5_cv_type_sigset_t,
[AC_TRY_COMPILE(
[#include <signal.h>],
[sigset_t x],
krb5_cv_type_sigset_t=yes, krb5_cv_type_sigset_t=no)])
AC_MSG_RESULT($krb5_cv_type_sigset_t)
if test $krb5_cv_type_sigset_t = yes; then
  AC_DEFINE(POSIX_SIGNALS)
fi
)])dnl
dnl
dnl check for signal type
dnl
dnl AC_RETSIGTYPE isn't quite right, but almost.
define(KRB5_SIGTYPE,
AC_MSG_CHECKING([POSIX signal handlers])
AC_CACHE_VAL(krb5_cv_has_posix_signals,
[AC_TRY_COMPILE(
[#include <sys/types.h>
#include <signal.h>
#ifdef signal
#undef signal
#endif
extern void (*signal ()) ();], [],
krb5_cv_has_posix_signals=yes, krb5_cv_has_posix_signals=no)])
AC_MSG_RESULT($krb5_cv_has_posix_signals)
if test $krb5_cv_has_posix_signals = yes; then
   AC_DEFINE(krb5_sigtype, void) AC_DEFINE(POSIX_SIGTYPE)
else
  if test $ac_cv_type_signal = void; then
     AC_DEFINE(krb5_sigtype, void)
  else
     AC_DEFINE(krb5_sigtype, int)
  fi
fi)dnl
dnl
dnl check for POSIX setjmp/longjmp -- CHECK_SETJMP
dnl
define(CHECK_SETJMP,[
AC_FUNC_CHECK(sigsetjmp,
AC_MSG_CHECKING(for sigjmp_buf)
AC_CACHE_VAL(krb5_cv_struct_sigjmp_buf,
[AC_TRY_COMPILE(
[#include <setjmp.h>],[sigjmp_buf x],
krb5_cv_struct_sigjmp_buf=yes,krb5_cv_struct_sigjmp_buf=no)])
AC_MSG_RESULT($krb5_cv_struct_sigjmp_buf)
if test $krb5_cv_struct_sigjmp_buf = yes; then
  AC_DEFINE(POSIX_SETJMP)
fi
)])dnl
dnl
dnl set $(KRB4) from --with-krb4=value -- WITH_KRB4
dnl
define(WITH_KRB4,[
AC_ARG_WITH([krb4],
[  --without-krb4          don't include Kerberos V4 backwards compatibility
  --with-krb4             use V4 libraries included with V5 (default)
  --with-krb4=KRB4DIR     use preinstalled V4 libraries],
,
withval=yes
)dnl
if test $withval = no; then
	AC_MSG_RESULT(no krb4 support)
	KRB4_LIB=
	DEPKRB4_LIB=
	KRB4_CRYPTO_LIB=
	DEPKRB4_CRYPTO_LIB=
	KDB4_LIB=
	DEPKDB4_LIB=
	LDARGS=
	krb5_cv_build_krb4_libs=no
	krb5_cv_krb4_libdir=
else 
 ADD_DEF(-DKRB5_KRB4_COMPAT)
 if test $withval = yes; then
	AC_MSG_RESULT(built in krb4 support)
	KRB4_LIB='-lkrb4'
	DEPKRB4_LIB='$(TOPLIBD)/libkrb4.a'
	KRB4_CRYPTO_LIB='-ldes425'
	DEPKRB4_CRYPTO_LIB='$(TOPLIBD)/libdes425.a'
	KDB4_LIB='-lkdb4'
	DEPKDB4_LIB='$(TOPLIBD)/libkdb4.a'
	LDARGS=
	krb5_cv_build_krb4_libs=yes
	krb5_cv_krb4_libdir=
 else
	AC_MSG_RESULT(preinstalled krb4 in $withval)
	KRB4_LIB="-lkrb"
	DEPKRB4_LIB="$withval/lib/libkrb.a"
	KRB4_CRYPTO_LIB='-ldes425'
	DEPKRB4_CRYPTO_LIB='$(TOPLIBD)/libdes425.a'
	KDB4_LIB="-lkdb"
	DEPKDB4_LIB="$withval/lib/libkdb.a"
	LDARGS="-L$withval/lib"
	krb5_cv_build_krb4_libs=no
	krb5_cv_krb4_libdir="$withval/lib"
 fi
fi
AC_SUBST(KRB4_LIB)
AC_SUBST(KDB4_LIB)
AC_SUBST(KRB4_CRYPTO_LIB)
AC_SUBST(DEPKRB4_LIB)
AC_SUBST(DEPKDB4_LIB)
AC_SUBST(DEPKRB4_CRYPTO_LIB)
])dnl
dnl
dnl set $(CC) from --with-cc=value
dnl
define(WITH_CC,[
AC_ARG_WITH([cc],
[  --with-cc=COMPILER      select compiler to use],
AC_MSG_RESULT(CC=$withval)
CC=$withval,
if test -z "$CC" ; then CC=cc; fi
[AC_MSG_RESULT(CC defaults to $CC)])dnl
AC_SUBST([CC])])dnl
dnl
dnl set $(LD) from --with-linker=value
dnl
define(WITH_LINKER,[
AC_ARG_WITH([linker],
[  --with-linker=LINKER    select linker to use],
AC_MSG_RESULT(LD=$withval)
LD=$withval,
if test -z "$LD" ; then LD=$CC; fi
[AC_MSG_RESULT(LD defaults to $LD)])dnl
AC_SUBST([LD])])dnl
dnl
dnl set $(CCOPTS) from --with-ccopts=value
dnl
define(WITH_CCOPTS,[
AC_ARG_WITH([ccopts],
[  --with-ccopts=CCOPTS    select compiler command line options],
AC_MSG_RESULT(CCOPTS is $withval)
CCOPTS=$withval
CFLAGS="$CFLAGS $withval",
CCOPTS=)dnl
AC_SUBST(CCOPTS)])dnl
dnl
dnl set $(LDFLAGS) from --with-ldopts=value
dnl
define(WITH_LDOPTS,[
AC_ARG_WITH([ldopts],
[  --with-ldopts=LDOPTS    select linker command line options],
AC_MSG_RESULT(LDFLAGS is $withval)
LDFLAGS=$withval,
LDFLAGS=)dnl
AC_SUBST(LDFLAGS)])dnl
dnl
dnl set $(CPPOPTS) from --with-cppopts=value
dnl
define(WITH_CPPOPTS,[
AC_ARG_WITH([cppopts],
[  --with-cppopts=CPPOPTS  select compiler preprocessor command line options],
AC_MSG_RESULT(CPPOPTS=$withval)
CPPOPTS=$withval
CPPFLAGS="$CPPFLAGS $withval",
[AC_MSG_RESULT(CPPOPTS defaults to $CPPOPTS)])dnl
AC_SUBST(CPPOPTS)])dnl
dnl
dnl Imake LinkFile rule, so they occur in the right place -- LinkFile(dst,src)
dnl
define(LinkFile,[
AC_LN_S
AC_PUSH_MAKEFILE()dnl
changequote({,})dnl

$1:: $2{
	$(RM) $}{@
	$(LN) $}{? $}{@

}
changequote([,])dnl
AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl Like above, but specifies how to get from link target to source, e.g.
dnl LinkFileDir(../foo, blotz, ./bar) issues a:
dnl	ln -s ../foo ./bar/blotz
dnl
define(LinkFileDir,[
AC_LN_S
AC_PUSH_MAKEFILE()dnl
changequote({,})dnl

$1:: $2{
	$(RM) $}{@
	$(LN) }$3{$(S)$}{? $}{@

}
changequote([,])dnl
AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl explicit append text (for non-general things) -- AppendRule(txt)
dnl
define(AppendRule,[
AC_PUSH_MAKEFILE()dnl

$1

AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl create DONE file for lib/krb5 -- SubdirLibraryRule(list)
define(SubdirLibraryRule,[
AC_PUSH_MAKEFILE()dnl

all:: DONE

DONE:: $1
	@if test x'$1' = x && test -r [$]@; then :;\
	else \
		(set -x; echo $1 > [$]@) \
	fi

clean::
	$(RM) DONE
AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl copy header file into include dir -- CopyHeader(hfile,hdir)
dnl
define(CopyHeader,[
AC_PUSH_MAKEFILE()dnl

includes:: $1
	@if test -d $2; then :; else (set -x; mkdir $2) fi
	@if cmp $1 $2/$1 >/dev/null 2>&1; then :; \
	else \
		(set -x; [$](RM) $2/$1;	[$](CP) $1 $2/$1) \
	fi

clean::
	$(RM) $2/$1

AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl copy source header file into include dir -- CopySrcHeader(hfile,hdir)
dnl
define(CopySrcHeader,[
AC_PUSH_MAKEFILE()dnl

includes:: $1
	@if test -d $2; then :; else (set -x; mkdir $2) fi
	@if cmp $(srcdir)/$1 $2/$1 >/dev/null 2>&1; then :; \
	else \
		(set -x; [$](RM) $2/$1;	[$](CP) $(srcdir)/$1 $2/$1) \
	fi

clean::
	$(RM) $2/$1

AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl Krb5InstallHeaders(headers,destdir)
define(Krb5InstallHeaders,[
AC_PUSH_MAKEFILE()dnl
install:: $1
	@set -x; for f in $1 ; \
	do [$](INSTALL_DATA) [$$]f $2/[$$]f ; \
	done
AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl arbitrary DEFS -- ADD_DEF(value)
dnl
define(ADD_DEF,[
CPPFLAGS="[$]CPPFLAGS "'$1'
])dnl
dnl
dnl local includes are used -- KRB_INCLUDE
dnl
define(KRB_INCLUDE,[
ADD_DEF([-I$(BUILDTOP)/include -I$(SRCTOP)/include -I$(BUILDTOP)/include/krb5 -I$(SRCTOP)/include/krb5])dnl
])dnl
dnl
dnl check for yylineno -- HAVE_YYLINENO
dnl
define(HAVE_YYLINENO,[dnl
AC_REQUIRE_CPP()AC_REQUIRE([AC_PROG_LEX])dnl
AC_MSG_CHECKING([for yylineno declaration])
AC_CACHE_VAL(krb5_cv_type_yylineno,
# some systems have yylineno, others don't...
  echo '%%
%%' | ${LEX} -t > conftest.out
  if egrep yylineno conftest.out >/dev/null 2>&1; then
	krb5_cv_type_yylineno=yes
  else
	krb5_cv_type_yylineno=no
  fi
  rm -f conftest.out)
  AC_MSG_RESULT($krb5_cv_type_yylineno)
  if test $krb5_cv_type_yylineno = no; then
	AC_DEFINE([NO_YYLINENO])
  fi
])dnl
dnl
dnl fix AC_PROG_LEX
dnl
undefine([AC_PROG_LEX])dnl
define(AC_PROG_LEX,
[AC_PROVIDE([$0])dnl
AC_PROGRAM_CHECK(LEX, flex, flex, lex)dnl
if test -z "$LEXLIB"
then
   case "$LEX" in
   flex*) AC_CHECK_LIB(fl,main, LEXLIB="-lfl") ;;
   *) AC_CHECK_LIB(l,main, LEXLIB="-ll") ;;
   esac
fi
AC_MSG_RESULT(setting LEXLIB to $LEXLIB)
AC_SUBST(LEX)AC_SUBST(LEXLIB)])dnl
dnl
dnl V5_OUTPUT_MAKEFILE
dnl
define(V5_AC_OUTPUT_MAKEFILE,
[AC_OUTPUT(pre.out:[$]ac_prepend Makefile.out:Makefile.in post.out:[$]ac_postpend,
[cat pre.out Makefile.out post.out > Makefile
EOF
dnl This should be fixed so that the here document produced gets broken up
dnl into chunks that are the "right" size, in case we run across shells that
dnl are broken WRT large here documents.
>> append.out
cat - append.out >> $CONFIG_STATUS <<\EOF
cat >> Makefile <<\CEOF
#
# rules appended by configure

EOF
rm append.out
dnl now back to regular config.status generation
cat >> $CONFIG_STATUS <<\EOF
CEOF
# sed -f $CONF_FRAGDIR/mac-mf.sed < Makefile > MakeFile
rm pre.out Makefile.out post.out
],
CONF_FRAGDIR=$srcdir/${ac_config_fragdir} )])dnl
dnl
dnl CHECK_UTMP: check utmp structure and functions
dnl
define(CHECK_UTMP,[
AC_MSG_CHECKING([ut_pid in struct utmp])
AC_CACHE_VAL(krb5_cv_struct_ut_pid,
[AC_TRY_COMPILE(
[#include <sys/types.h>
#include <utmp.h>],
[struct utmp ut; ut.ut_pid;],
krb5_cv_struct_ut_pid=yes, krb5_cv_struct_ut_pid=no)])
AC_MSG_RESULT($krb5_cv_struct_ut_pid)
if test $krb5_cv_struct_ut_pid = no; then
  AC_DEFINE(NO_UT_PID)
fi
AC_MSG_CHECKING([ut_type in struct utmp])
AC_CACHE_VAL(krb5_cv_struct_ut_type,
[AC_TRY_COMPILE(
[#include <sys/types.h>
#include <utmp.h>],
[struct utmp ut; ut.ut_type;],
krb5_cv_struct_ut_type=yes, krb5_cv_struct_ut_type=no)])
AC_MSG_RESULT($krb5_cv_struct_ut_type)
if test $krb5_cv_struct_ut_type = no; then
  AC_DEFINE(NO_UT_TYPE)
fi
AC_MSG_CHECKING([ut_host in struct utmp])
AC_CACHE_VAL(krb5_cv_struct_ut_host,
[AC_TRY_COMPILE(
[#include <sys/types.h>
#include <utmp.h>],
[struct utmp ut; ut.ut_host;],
krb5_cv_struct_ut_host=yes, krb5_cv_struct_ut_host=no)])
AC_MSG_RESULT($krb5_cv_struct_ut_host)
if test $krb5_cv_struct_ut_host = no; then
  AC_DEFINE(NO_UT_HOST)
fi
AC_MSG_CHECKING([ut_exit in struct utmp])
AC_CACHE_VAL(krb5_cv_struct_ut_exit,
[AC_TRY_COMPILE(
[#include <sys/types.h>
#include <utmp.h>],
[struct utmp ut; ut.ut_exit;],
krb5_cv_struct_ut_exit=yes, krb5_cv_struct_ut_exit=no)])
AC_MSG_RESULT($krb5_cv_struct_ut_exit)
if test $krb5_cv_struct_ut_exit = no; then
  AC_DEFINE(NO_UT_EXIT)
fi
AC_FUNC_CHECK(setutent,AC_DEFINE(HAVE_SETUTENT))
AC_FUNC_CHECK(setutxent,AC_DEFINE(HAVE_SETUTXENT))
AC_FUNC_CHECK(updwtmp,AC_DEFINE(HAVE_UPDWTMP))
AC_FUNC_CHECK(updwtmpx,AC_DEFINE(HAVE_UPDWTMPX))
])dnl
dnl
dnl
dnl Check for POSIX_FILE_LOCKS - used be include/krb5 and appl/popper
dnl
AC_DEFUN([KRB5_POSIX_LOCKS],[dnl
AC_HEADER_CHECK(flock.h,[echo found flock.h for non-posix locks],
  [AC_MSG_CHECKING([POSIX file locking -- structs and flags])
  AC_CACHE_VAL(krb5_cv_struct_flock,
[AC_TRY_LINK(dnl
[#include <sys/types.h>
#include <fcntl.h>],
[struct flock f; 1+F_SETLK;], 
  krb5_cv_struct_flock=yes, krb5_cv_struct_flock=no)])
  AC_MSG_RESULT($krb5_cv_struct_flock)
  if test $krb5_cv_struct_flock = yes; then
    AC_DEFINE(POSIX_FILE_LOCKS)
  fi
])])dnl
dnl
dnl WITH_NETLIB
dnl 
dnl
define(WITH_NETLIB,[
AC_ARG_WITH([netlib],
[  --with-netlib[=libs]    use user defined resolve library],
  if test "$withval" = yes -o "$withval" = no ; then
	AC_MSG_RESULT("netlib will link with C library resolver only")
  else
	LIBS="$LIBS $withval"
	AC_MSG_RESULT("netlib will use \'$withval\'")
  fi
,dnl
[AC_CHECK_LIB(socket,main)
AC_CHECK_LIB(nsl,main)]
)])dnl
dnl
dnl HAS_ANSI_VOLATILE
dnl
define(HAS_ANSI_VOLATILE,[
AC_MSG_CHECKING([volatile])
AC_CACHE_VAL(krb5_cv_has_ansi_volatile,
[AC_TRY_COMPILE(
[volatile int x();], [],
krb5_cv_has_ansi_volatile=yes, krb5_cv_has_ansi_volatile=no)])
AC_MSG_RESULT($krb5_cv_has_ansi_volatile)
if test $krb5_cv_has_ansi_volatile = no; then
ADD_DEF(-Dvolatile=)
fi
])dnl
dnl
dnl This rule tells KRB5_LIBRARIES to use the kadm librarh.
dnl
kadm_deplib=''
kadm_lib=''
define(USE_KADM_LIBRARY,[
kadm_deplib="[$](TOPLIBD)/libkadm.a"
kadm_lib=-lkadm])
dnl
dnl This rule tells KRB5_LIBRARIES to include the kdb5 library.
dnl
kdb5_deplib=''
kdb5_lib=''
define(USE_KDB5_LIBRARY,[
kdb5_deplib="[$](TOPLIBD)/libkdb5.a"
kdb5_lib=-lkdb5])
dnl
dnl This rule tells KRB5_LIBRARIES to include the kdb4 library.
dnl
kdb4_deplib=''
kdb4_lib=''
define(USE_KDB4_LIBRARY,[
kdb4_deplib=$DEPKRB4_LIB
kdb4_lib=$KDB4_LIB])
dnl
dnl This rule tells KRB5_LIBRARIES to include the krb4 libraries.
dnl
krb4_deplib=''
krb5_lib=''
define(USE_KRB4_LIBRARY,[
krb4_deplib="$DEPKRB4_LIB $DEPKRB4_CRYPTO_LIB"
krb4_lib="$KRB4_LIB $KRB4_CRYPTO_LIB"])
dnl
dnl This rule tells KRB5_LIBRARIES to include the ss library.
dnl
ss_deplib=''
ss_lib=''
define(USE_SS_LIBRARY,[
ss_deplib="[$](TOPLIBD)/libss.a"
ss_lib=-lss
])
dnl
dnl This rule generates library lists for programs.
dnl
define(KRB5_LIBRARIES,[
DEPLIBS="[$](DEPLOCAL_LIBRARIES) $kadm_deplib $kdb5_deplib [$](TOPLIBD)/libkrb5.a $kdb4_deplib $krb4_deplib [$](TOPLIBD)/libcrypto.a $ss_deplib [$](TOPLIBD)/libcom_err.a"
LIBS="[$](LOCAL_LIBRARIES) $kadm_lib $kdb5_lib -lkrb5 $kdb4_lib $krb4_lib -lcrypto $ss_lib -lcom_err $LIBS"
AC_SUBST(DEPLIBS)])
dnl
dnl This rule supports the generation of the shared library object files
dnl
define(V5_SHARED_LIB_OBJS,[
if test ${krb5_cv_shlibs_dir}x != x; then
SHARED_RULE="	\$(CC) ${krb5_cv_shlibs_cflags} \$(CFLAGS) -o ${krb5_cv_shlibs_dir}/\$""*.o -c \$""<"
SHARED_RULE_LOCAL="	\$(CC) ${krb5_cv_shlibs_cflags} \$(CFLAGS) -o ${krb5_cv_shlibs_dir}/\$""*.o -c \$""<"
else
SHARED_RULE=
SHARED_RULE_LOCAL=
fi
AC_SUBST(SHARED_RULE)
AC_SUBST(SHARED_RULE_LOCAL)
])dnl
dnl
dnl This rule adds the additional Makefile fragment necessary to actually 
dnl create the shared library
dnl
define(V5_MAKE_SHARED_LIB,[
if test "[$]krb5_cv_staticlibs_enabled" = yes
	then
	SHLIB_STATIC_TARGET="$1.[\$](STEXT)"
	else
	SHLIB_STATIC_TARGET=
	fi
AC_ARG_ENABLE([shared],
[  --enable-shared         build with shared libraries],[
SHLIB_TAIL_COMP=$krb5_cv_shlibs_tail_comp
AC_SUBST(SHLIB_TAIL_COMP)
LD_UNRESOLVED_PREFIX=$krb5_cv_shlibs_sym_ufo
AC_SUBST(LD_UNRESOLVED_PREFIX)
LD_SHLIBDIR_PREFIX=$krb5_cv_shlibs_dirhead
AC_SUBST(LD_SHLIBDIR_PREFIX)
SHLIB_RPATH_DIRS=
if test $krb5_cv_shlibs_use_dirs = yes ; then
	SHLIB_RPATH_DIRS="$krb5_cv_shlibs_dirhead \$(KRB5_SHLIBDIR) $krb5_cv_shlibs_dirhead `pwd`/\$(TOPLIBD)"
fi
AC_SUBST(SHLIB_RPATH_DIRS)
SHLIB_LIBDIRS="-L\$(TOPLIBD)"
if test X$krb5_cv_krb4_libdir != X ; then
	SHLIB_LIBDIRS="$SHLIB_LIBDIRS -L$krb5_cv_krb4_libdir"
fi
AC_SUBST(SHLIB_LIBDIRS)
HOST_TYPE=$krb5_cv_host
AC_SUBST(HOST_TYPE)
SHEXT=$krb5_cv_shlibs_ext
AC_SUBST(SHEXT)
STEXT=$krb5_cv_noshlibs_ext
AC_SUBST(STEXT)
DO_MAKE_SHLIB="$1.\$""(SHEXT)"
AC_PUSH_MAKEFILE()dnl

all:: [$](DO_MAKE_SHLIB) [$](SHLIB_STATIC_TARGET)

clean:: 
	$(RM) $1.[$](SHEXT) [$](SHLIB_STATIC_TARGET)

$1.[$](SHEXT): [$](LIBDONE) [$](DEPLIBS)
	[$](BUILDTOP)/util/makeshlib [$]@	\
		"[$](SHLIB_LIBDIRS)" \
		"[$](SHLIB_LIBS)" "[$](SHLIB_LDFLAGS)" [$](LIB_SUBDIRS)

AC_POP_MAKEFILE()dnl
],[
STEXT=$krb5_cv_noshlibs_ext
AC_SUBST(STEXT)
DO_MAKE_SHLIB=
AC_PUSH_MAKEFILE()
all:: [$](DO_MAKE_SHLIB) [$](SHLIB_STATIC_TARGET)

clean:: 
	$(RM) $1.[$](STEXT)
AC_POP_MAKEFILE()
])dnl
AC_SUBST(DO_MAKE_SHLIB)
AC_SUBST(SHLIB_STATIC_TARGET)])dnl
dnl
dnl Defines LDARGS correctly so that we actually link with the shared library
dnl
define(V5_USE_SHARED_LIB,[
AC_ARG_WITH([shared],
[  --with-shared	use shared libraries (default)
  --without-shared	don't use shared libraries],
,
withval=yes
)dnl
if test "$krb5_cv_shlibs_enabled" = yes ; then
  if test "$withval" = yes; then
	AC_MSG_RESULT(Using shared libraries)
	LDARGS="$krb5_cv_shlibs_ldflag -L\$(TOPLIBD) $LDARGS"
	if test "$krb5_cv_exe_need_dirs" = yes; then
		LDARGS="$LDARGS $krb5_cv_shlibs_dirhead \$(KRB5_SHLIBDIR) $krb5_cv_shlibs_dirhead `pwd`/\$(TOPLIBD)"
	fi
	SHLIB_TAIL_COMP=$krb5_cv_shlibs_tail_comp
	AC_SUBST(SHLIB_TAIL_COMP)
  else
	AC_MSG_RESULT(Using archive libraries)
	LDARGS="$krb5_cv_noshlibs_ldflag -L\$(TOPLIBD) $LDARGS"
  fi
else
  LDARGS="-L\$(TOPLIBD) $LDARGS"
fi
AC_SUBST(LDARGS)
])dnl

dnl
dnl
dnl arrange to stuff file in substitution
dnl
dnl AC_STUFF_FILE_PRE()
define(AC_STUFF_FILE_PRE,
[AC_DIVERT_PUSH(AC_DIVERSION_SED)dnl
1r $1
AC_DIVERT_POP()dnl
])
dnl AC_STUFF_FILE_POST()
define(AC_STUFF_FILE_POST,
[AC_DIVERT_PUSH(AC_DIVERSION_SED)dnl
[$]r $1
AC_DIVERT_POP()dnl
])
dnl
dnl look for the top of the tree
dnl
AC_DEFUN(AC_CONFIG_FRAGMENTS_DEFAULT,
[AC_CONFIG_FRAGMENTS(. .. ../.. ../../.. ../../../.. ../../../../.. ../../../../../..)])dnl
dnl
dnl search them looking for the directory named config.
dnl Crude, but it works.
dnl
AC_DEFUN(AC_CONFIG_FRAGMENTS,
[ac_config_fragdir=
for ac_dir in $1; do
  if test -d $srcdir/$ac_dir/config; then
    ac_reltopdir=$ac_dir
    ac_topdir=$srcdir/$ac_reltopdir
    ac_config_fragdir=$ac_reltopdir/config
    break
  fi
done
if test -z "$ac_config_fragdir"; then
  AC_MSG_ERROR([can not find config/ directory in $1])
else
  AC_CONFIG_AUX_DIR($ac_config_fragdir)
fi
  ac_tmpin="$srcdir/${ac_config_fragdir}/pre.in"
  if test -r $ac_tmpin; then
     ac_prepend=$ac_config_fragdir/pre.in
  else
     ac_prepend=
  fi
  ac_tmpin="$srcdir/${ac_config_fragdir}/post.in"
  if test -r $ac_tmpin; then
     ac_postpend=$ac_config_fragdir/post.in
  else
     ac_postpend=
  fi
AC_PROVIDE([AC_CONFIG_FRAGMENTS_DEFAULT])dnl
])
dnl
dnl
dnl set up buildtop stuff
dnl
define(AC_BUILDTOP,[.])dnl
define(AC_SET_BUILDTOP,
[AC_CONFIG_FRAGMENTS_DEFAULT()dnl
AC_SUBST(BUILDTOP)dnl
BUILDTOP=[$]ac_reltopdir
])dnl
dnl
dnl
dnl
dnl
dnl How do we find other scripts needed for configuration?
dnl Scripts like Cygnus configure, config.sub, config.guess are stored
dnl together in one directory.  For now, have the configure.in file
dnl specify it explicitly with AC_CONFIG_AUX.  We'll provide a half-way
dnl acceptable default of ${srcdir}.
dnl
define(AC__CONFIG_AUX,[
  if test "z${config_sub}" = "z" ; then
    config_sub=${srcdir}/config.sub
  fi
  if test "z${config_guess}" = "z" ; then
    config_guess=${srcdir}/config.guess
  fi
AC_PROVIDE([$0])dnl
])dnl
dnl
dnl Does configure need to be run in immediate subdirectories of this
dnl directory?
dnl
define(CONFIG_DIRS,[AC_CONFIG_SUBDIRS($1)])dnl
dnl
dnl
dnl append subdir rule -- MAKE_SUBDIRS("making",all)
dnl
define(AC_DIVERSION_MAKEFILE,9)dnl   things that get pushed on the makefile
dnl
define(_MAKE_SUBDIRS,[
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl
changequote(<<<,>>>)dnl

$2::<<<
	@case '${MFLAGS}' in *[ik]*) set +e ;; esac; \
	for i in $(SUBDIRS) ;\
	do \
		(cd $$i ; echo>>> $1 <<<"in $(CURRENT_DIR)$$i..."; \
			$(MAKE) $(MFLAGS) CC="$(CC)" CCOPTS="$(CCOPTS)" \
			CURRENT_DIR=$(CURRENT_DIR)$$i/ >>>$3<<<) || exit 1; \
	done>>>
changequote([,])dnl
AC_DIVERT_POP()dnl
])dnl
define(MAKE_SUBDIRS,[
_MAKE_SUBDIRS($1, $2, $2)])dnl
dnl
dnl take saved makefile stuff and put it in the Makefile
dnl
define(EXTRA_RULES,[
cat >> Makefile <<"SUBDIREOF"
# [DIVERSION_MAKEFILE] contents
undivert(AC_DIVERSION_MAKEFILE)
SUBDIREOF
])dnl
dnl
dnl take saved makefile stuff and put it in the argument
dnl
define(EXTRA_RULES_IN,[
cat >> $1 <<"SUBDIREOF"
# [DIVERSION_MAKEFILE] contents
undivert(AC_DIVERSION_MAKEFILE)
SUBDIREOF
])dnl
dnl
dnl take saved makefile stuff and put it in the argument
dnl
define(EXTRA_RULES_OUT,[
cat > $1 <<"SUBDIREOF"
# [DIVERSION_MAKEFILE] contents
undivert(AC_DIVERSION_MAKEFILE)
SUBDIREOF
])dnl
dnl
dnl drop in standard configure rebuild rules -- CONFIG_RULES
dnl
define(CONFIG_RULES,[
WITH_CC dnl
WITH_LINKER dnl
WITH_CPPOPTS dnl
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl
[
SHELL=/bin/sh

Makefile: $(srcdir)/Makefile.in config.status $(SRCTOP)/config/pre.in $(SRCTOP)/config/post.in
	$(SHELL) config.status
config.status: $(srcdir)/configure
	$(SHELL) config.status --recheck
$(srcdir)/configure: $(srcdir)/configure.in $(SRCTOP)/aclocal.m4
	cd $(srcdir); $(SRCTOP)/util/autoconf/autoconf --localdir=$(BUILDTOP) --macrodir=$(BUILDTOP)/util/autoconf
]
AC_DIVERT_POP()dnl
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
])
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
define(AC_PROG_ARCHIVE, [AC_PROGRAM_CHECK(ARCHIVE, ar, ar qv, false)])dnl
define(AC_PROG_ARCHIVE_ADD, [AC_PROGRAM_CHECK(ARADD, ar, ar cruv, false)])dnl
dnl
dnl drop in rules for building error tables -- ET_RULES
dnl
define(ET_RULES,[
AC_PROG_AWK dnl
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl
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
AC_DIVERT_POP()dnl
])dnl
dnl
dnl drop in rules for building command tables -- SS_RULES
dnl
define(SS_RULES,[
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl
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
AC_DIVERT_POP()dnl
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
])
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
dnl set $(KRB5ROOT) from --with-krb5-root=value -- WITH_KRB5ROOT
dnl
define(WITH_KRB5ROOT,[
AC_ARG_WITH([krb5-root],
[  --with-krb5-root=DIR    set path for Kerberos V5 config files],
AC_MSG_RESULT(krb5-root is $withval)
KRB5ROOT=$withval,
AC_MSG_RESULT(krb5-root defaults to /krb5)
KRB5ROOT=/krb5)dnl
AC_SUBST(KRB5ROOT)])dnl
dnl
dnl set $(KRB4) from --with-krb4=value -- WITH_KRB4
dnl
define(WITH_KRB4,[
AC_ARG_WITH([krb4],
[  --with-krb4=KRB4DIR     build with Kerberos V4 backwards compatibility],
AC_MSG_RESULT(krb4 is $withval)
KRB4=$withval,
AC_MSG_RESULT(no krb4 support; use --with-krb4=krb4dir)
KRB4=)dnl
AC_SUBST(KRB4)])dnl
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
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl
changequote({,})dnl

$1:: $2{
	$(RM) $}{@
	$(LN) $}{? $}{@

}
changequote([,])dnl
AC_DIVERT_POP()dnl
])dnl
dnl
dnl explicit append text (for non-general things) -- AppendRule(txt)
dnl
define(AppendRule,[
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl

$1

AC_DIVERT_POP()dnl
])dnl
dnl
dnl create DONE file for lib/krb5 -- SubdirLibraryRule(list)
define(SubdirLibraryRule,[
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl

all:: DONE

DONE:: $1
	echo $1 > [$]@

clean::
	$(RM) DONE
AC_DIVERT_POP()dnl
])dnl
dnl
dnl copy header file into include dir -- CopyHeader(hfile,hdir)
dnl
define(CopyHeader,[
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl

includes:: $1
	@if test -d $2; then :; else (set -x; mkdir $2) fi
	@if cmp $1 $2/$1 >/dev/null 2>&1; then :; \
	else \
		(set -x; [$](RM) $2/$1;	[$](CP) $1 $2/$1) \
	fi

clean::
	$(RM) $2/$1

AC_DIVERT_POP()dnl
])dnl
dnl
dnl copy source header file into include dir -- CopySrcHeader(hfile,hdir)
dnl
define(CopySrcHeader,[
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl

includes:: $1
	@if test -d $2; then :; else mkdir $2; fi
	@if cmp $(srcdir)/$1 $2/$1 >/dev/null 2>&1; then :; \
	else \
		(set -x; [$](RM) $2/$1;	[$](CP) $(srcdir)/$1 $2/$1) \
	fi

clean::
	$(RM) $2/$1

AC_DIVERT_POP()dnl
])dnl
dnl
dnl Krb5InstallHeaders(headers,destdir)
define(Krb5InstallHeaders,[
AC_DIVERT_PUSH(AC_DIVERSION_MAKEFILE)dnl
install:: $1
	@set -x; for f in $1 ; \
	do [$](INSTALL_DATA) [$$]f $2/[$$]f ; \
	done
AC_DIVERT_POP()dnl
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
ADD_DEF([-I$(SRCTOP)/include -I$(BUILDTOP)/include -I$(SRCTOP)/include/krb5 -I$(BUILDTOP)/include/krb5])dnl
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
dnl make this one deeper...
dnl
dnl The default is `$srcdir' or `$srcdir/..' or `$srcdir/../..'.
dnl There's no need to call this macro explicitly; just AC_REQUIRE it.
AC_DEFUN(AC_CONFIG_AUX_DIR_DEFAULT,
[AC_CONFIG_AUX_DIRS($srcdir $srcdir/.. $srcdir/../.. $srcdir/../../.. $srcdir/../../../.. $srcdir/../../../../..)])
dnl
dnl V5_OUTPUT_MAKEFILE
dnl
define(V5_AC_OUTPUT_MAKEFILE,
[AC_OUTPUT(pre.out:[$]ac_prepend Makefile.out:Makefile.in post.out:[$]ac_postpend,
cat pre.out Makefile.out post.out > Makefile
[EXTRA_RULES]
# sed -f $CONF_FRAGDIR/mac-mf.sed < Makefile > MakeFile
rm pre.out Makefile.out post.out,
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

AC_PREREQ(2.12)
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
krb5_prepend_frags=$ac_config_fragdir/pre.in
krb5_append_frags=$ac_config_fragdir/post.in
BUILDTOP=$ac_reltopdir
SRCTOP=$srcdir/$ac_reltopdir
if test -d "$srcdir/$ac_config_fragdir"; then
  AC_CONFIG_AUX_DIR($ac_config_fragdir)
else
  AC_MSG_ERROR([can not find config/ directory in $ac_reltopdir])
fi
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
dnl DO_SUBDIRS
dnl recurse into subdirs by specifying the recursion targets
dnl the rules are in post.in but the target needs substitution
AC_DEFUN([DO_SUBDIRS],
[# this is a noop now
])

dnl
dnl drop in standard rules for all configure files -- CONFIG_RULES
dnl
define(CONFIG_RULES,[dnl
V5_SET_TOPDIR dnl
WITH_CC dnl
WITH_CCOPTS dnl
WITH_LINKER dnl
WITH_LDOPTS dnl
WITH_CPPOPTS dnl
WITH_KRB4 dnl
AC_CONST dnl
WITH_NETLIB dnl
KRB_INCLUDE dnl
AC_ARG_PROGRAM dnl
AC_SUBST(subdirs)
])dnl

dnl This is somewhat gross and should go away when the build system
dnl is revamped. -- tlyu
dnl DECLARE_SYS_ERRLIST - check for sys_errlist in libc
dnl
AC_DEFUN([DECLARE_SYS_ERRLIST],
[AC_CACHE_CHECK([for sys_errlist declaration], krb5_cv_decl_sys_errlist,
[AC_TRY_COMPILE([#include <stdio.h>
#include <errno.h>], [1+sys_nerr;],
krb5_cv_decl_sys_errlist=yes, krb5_cv_decl_sys_errlist=no)])
# assume sys_nerr won't be declared w/o being in libc
if test $krb5_cv_decl_sys_errlist = yes; then
  AC_DEFINE(SYS_ERRLIST_DECLARED)
  AC_DEFINE(HAVE_SYS_ERRLIST)
else
  # This means that sys_errlist is not declared in errno.h, but may still
  # be in libc.
  AC_CACHE_CHECK([for sys_errlist in libc], krb5_cv_var_sys_errlist,
  [AC_TRY_LINK([extern int sys_nerr;], [1+sys_nerr;],
  krb5_cv_var_sys_errlist=yes, krb5_cv_var_sys_errlist=no;)])
  if test $krb5_cv_var_sys_errlist = yes; then
    AC_DEFINE(HAVE_SYS_ERRLIST)
    # Do this cruft for backwards compatibility for now.
    AC_DEFINE(NEED_SYS_ERRLIST)
  else
    AC_MSG_WARN([sys_errlist is neither in errno.h nor in libc])
  fi
fi])

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
dnl check for <dirent.h> -- CHECK_DIRENT
dnl (may need to be more complex later)
dnl
define(CHECK_DIRENT,[
AC_HEADER_CHECK(dirent.h,AC_DEFINE(USE_DIRENT_H))])dnl
dnl
dnl check if union wait is defined, or if WAIT_USES_INT -- CHECK_WAIT_TYPE
dnl
define(CHECK_WAIT_TYPE,[
AC_MSG_CHECKING([for union wait])
AC_CACHE_VAL(krb5_cv_struct_wait,
[AC_TRY_COMPILE(
[#include <sys/wait.h>], [union wait i;
#ifdef WEXITSTATUS
  WEXITSTATUS (i);
#endif
], 
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
define(KRB5_SIGTYPE,[
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
fi])dnl
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
	KRB4_DEPLIB=
	DES425_LIB=
	DES425_DEPLIB=
	KRB4_INCLUDES=
	KRB4_LIBPATH=
	krb5_cv_build_krb4_libs=no
	krb5_cv_krb4_libdir=
else 
 ADD_DEF(-DKRB5_KRB4_COMPAT)
 DES425_DEPLIB='$(TOPLIBD)/libdes425$(DEPLIBEXT)'
 DES425_LIB=-ldes425
 if test $withval = yes; then
	AC_MSG_RESULT(built in krb4 support)
	KRB4_DEPLIB='$(TOPLIBD)/libkrb4$(DEPLIBEXT)'
	KRB4_LIB=-lkrb4
	KRB4_INCLUDES='-I$(SRCTOP)/include/kerberosIV -I$(BUILDTOP)/include/kerberosIV'
	KRB4_LIBPATH=
	krb5_cv_build_krb4_libs=yes
	krb5_cv_krb4_libdir=
 else
	AC_MSG_RESULT(preinstalled krb4 in $withval)
	KRB4_LIB="-lkrb"
dnl	DEPKRB4_LIB="$withval/lib/libkrb.a"
	KRB4_INCLUDES="-I$withval/include"
	KRB4_LIBPATH="-L$withval/lib"
	krb5_cv_build_krb4_libs=no
	krb5_cv_krb4_libdir="$withval/lib"
 fi
fi
AC_SUBST(KRB4_INCLUDES)
AC_SUBST(KRB4_LIBPATH)
AC_SUBST(KRB4_LIB)
AC_SUBST(KRB4_DEPLIB)
AC_SUBST(DES425_DEPLIB)
AC_SUBST(DES425_LIB)
])dnl
dnl
dnl set $(CC) from --with-cc=value
dnl
define(WITH_CC,[
AC_ARG_WITH([cc],
[  --with-cc=COMPILER      select compiler to use])
AC_MSG_CHECKING(for C compiler)
if test "$with_cc" != ""; then
  if test "$ac_cv_prog_cc" != "" && test "$ac_cv_prog_cc" != "$with_cc"; then
    AC_MSG_ERROR(Specified compiler doesn't match cached compiler name;
	remove cache and try again.)
  else
    CC="$with_cc"
  fi
fi
AC_CACHE_VAL(ac_cv_prog_cc,[dnl
  test -z "$CC" && CC=cc
  AC_TRY_LINK([#include <stdio.h>],[printf("hi\n");], ,
    AC_MSG_ERROR(Can't find a working compiler.))
  ac_cv_prog_cc="$CC"
])
CC="$ac_cv_prog_cc"
AC_MSG_RESULT($CC)
AC_PROG_CC
])dnl
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
AC_REQUIRE([AC_LN_S])
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
AC_REQUIRE([AC_LN_S])
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

all-unix:: DONE

DONE:: $1 $(srcdir)/Makefile.in
	@if test x'$1' = x && test -r [$]@; then :;\
	else \
		(set -x; echo $1 > [$]@) \
	fi

clean-unix::
	$(RM) DONE
AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl copy header file into include dir -- CopyHeader(hfile,hdir)
dnl
define(CopyHeader,[
AC_PUSH_MAKEFILE()dnl

includes:: $2/$1
$2/$1: $1
	@if test -d $2; then :; else (set -x; mkdir $2) fi
	@if cmp $1 $2/$1 >/dev/null 2>&1; then :; \
	else \
		(set -x; [$](RM) $2/$1;	[$](CP) $1 $2/$1) \
	fi

clean-unix::
	$(RM) $2/$1

AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl copy source header file into include dir -- CopySrcHeader(hfile,hdir)
dnl
define(CopySrcHeader,[
AC_PUSH_MAKEFILE()dnl

includes:: $2/$1
$2/$1: $(srcdir)/$1
	@if test -d $2; then :; else (set -x; mkdir $2) fi
	@if cmp $(srcdir)/$1 $2/$1 >/dev/null 2>&1; then :; \
	else \
		(set -x; [$](RM) $2/$1;	[$](CP) $(srcdir)/$1 $2/$1) \
	fi

clean-unix::
	$(RM) $2/$1

AC_POP_MAKEFILE()dnl
])dnl
dnl
dnl Krb5InstallHeaders(headers,destdir)
define(Krb5InstallHeaders,[
AC_PUSH_MAKEFILE()dnl
install-unix:: $1
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
[ifelse($1, , ac_v5_makefile_dirs=., ac_v5_makefile_dirs="$1")
ifelse($2, , filelist="", filelist="$2")
dnl OPTIMIZE THIS FOR COMMON CASE!!
for x in $ac_v5_makefile_dirs; do
  filelist="$filelist $x/Makefile.tmp:$krb5_prepend_frags:$x/Makefile.in:$krb5_append_frags"
done
AC_OUTPUT($filelist,
[EOF
ac_reltopdir=`echo $ac_reltopdir | sed   \
	-e ':LOOP'		\
	-e 's,/\./,/,'		\
	-e 'tLOOP'		\
	-e 's,^\./,,'		\
	-e 's,/\.$,,g'		\
	`
test "$ac_reltopdir" = "" && ac_reltopdir=.
cat >> $CONFIG_STATUS <<EOF
ac_v5_makefile_dirs="$ac_v5_makefile_dirs"
ac_reltopdir=$ac_reltopdir
EOF
dnl This should be fixed so that the here document produced gets broken up
dnl into chunks that are the "right" size, in case we run across shells that
dnl are broken WRT large here documents.
>> append.out
cat - append.out >> $CONFIG_STATUS <<\EOF
cat >> append.tmp <<\CEOF
#
# rules appended by configure

EOF
rm append.out
dnl now back to regular config.status generation
cat >> $CONFIG_STATUS <<\EOF
CEOF
for d in $ac_v5_makefile_dirs; do
  # If CONFIG_FILES was set from Makefile, skip unprocessed directories.
  if test -r $d/Makefile.tmp; then
changequote(,)dnl
    x=`echo $d/ | sed   \
	-e 's,//*$,/,'		\
	-e ':LOOP'		\
	-e 's,/\./,/,'		\
	-e 'tLOOP'		\
	-e 's,^\./,,'		\
	-e 's,[^/]*/,../,g'	\
	`
changequote([,])dnl
    test "$x" = "" && x=./
    case $srcdir in
    /*)  s=$ac_given_srcdir/$ac_reltopdir ;;
    *)   s=$x$ac_given_srcdir/$ac_reltopdir ;;
    esac
    s=`echo $s | sed   \
	-e 's,//*$,/,'		\
	-e ':LOOP'		\
	-e 's,/\./,/,'		\
	-e 'tLOOP'		\
	-e 's,^\./,,'		\
	-e 's,/\.$,,g'		\
	`
    test "$s" = "" && s=.
    echo creating $d/Makefile
    cat - $d/Makefile.tmp append.tmp > $d/Makefile <<EOX
thisconfigdir=$x
SRCTOP=$s
BUILDTOP=$x$ac_reltopdir
EOX
    rm  $d/Makefile.tmp
# sed -f $CONF_FRAGDIR/mac-mf.sed < Makefile > MakeFile
  fi
done
rm append.tmp
],
CONF_FRAGDIR=$srcdir/${ac_config_fragdir} )])dnl
dnl
dnl KRB5_SOCKADDR_SA_LEN: define HAVE_SA_LEN if sockaddr contains the sa_len
dnl component
dnl
AC_DEFUN([KRB5_SOCKADDR_SA_LEN],[ dnl
AC_MSG_CHECKING(Whether struct sockaddr contains sa_len)
AC_CACHE_VAL(krb5_cv_sockaddr_sa_len,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
],
[struct sockaddr sa;
sa.sa_len;],
krb5_cv_sockaddr_sa_len=yes,krb5_cv_sockaddr_sa_len=no)])
AC_MSG_RESULT([$]krb5_cv_sockaddr_sa_len)
if test $krb5_cv_sockaddr_sa_len = yes; then
   AC_DEFINE_UNQUOTED(HAVE_SA_LEN)
   fi
])
dnl
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
[if test "`(uname) 2>/dev/null`" != IRIX ; then
  AC_CHECK_LIB(socket,main)
fi
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
dnl This rule tells KRB5_LIBRARIES to use the kadm5srv library.
dnl
kadmsrv_deplib=''
kadmsrv_lib=''
define(USE_KADMSRV_LIBRARY,[
kadmsrv_deplib="\[$](TOPLIBD)/libkadm5srv.a"
kadmsrv_lib=-lkadm5srv])
dnl
dnl This rule tells KRB5_LIBRARIES to use the kadm5clnt library.
dnl
kadmclnt_deplib=''
kadmclnt_lib=''
define(USE_KADMCLNT_LIBRARY,[
kadmclnt_deplib="\[$](TOPLIBD)/libkadm5clnt.a"
kadmclnt_lib=-lkadm5clnt])
dnl
dnl This rule tells KRB5_LIBRARIES to use the gssrpc library.
dnl
gssrpc_deplib=''
gssrpc_lib=''
define(USE_GSSRPC_LIBRARY,[
gssrpc_deplib="\[$](TOPLIBD)/libgssrpc.a"
gssrpc_lib=-lgssrpc])
dnl
dnl This rule tells KRB5_LIBRARIES to use the gssapi library.
dnl
gssapi_deplib=''
gssapi_lib=''
define(USE_GSSAPI_LIBRARY,[
gssapi_deplib="\[$](TOPLIBD)/libgssapi_krb5.a"
gssapi_lib=-lgssapi_krb5])
dnl
dnl This rule tells KRB5_LIBRARIES to use the krb5util library.
dnl
kutil_deplib=''
kutil_lib=''
define(USE_KRB5UTIL_LIBRARY,[
kutil_deplib="\[$](TOPLIBD)/libkrb5util.a"
kutil_lib=-lkrb5util])
dnl
dnl This rule tells KRB5_LIBRARIES to include the aname db library.
dnl
define(USE_ANAME,[
USE_DB_LIBRARY
])dnl
dnl
dnl This rule tells KRB5_LIBRARIES to include the kdb5 and db libraries.
dnl
kdb5_deplib=''
kdb5_lib=''
define(USE_KDB5_LIBRARY,[
kdb5_deplib="\[$](TOPLIBD)/libkdb5.a"
kdb5_lib=-lkdb5
USE_DB_LIBRARY
])
dnl
dnl This rule tells KRB5_LIBRARIES to include the krb4 libraries.
dnl
krb4_deplib=''
krb5_lib=''
define(USE_KRB4_LIBRARY,[
krb4_deplib="$DEPKRB4_LIB $DEPKRB4_CRYPTO_LIB"
krb4_lib="$KRB4_LIB $KRB4_CRYPTO_LIB"]
	CPPFLAGS="$CPPFLAGS $KRB4_INCLUDE") dnl
dnl
dnl This rule tells KRB5_LIBRARIES to include the ss library.
dnl
ss_deplib=''
ss_lib=''
define(USE_SS_LIBRARY,[
ss_deplib="\[$](TOPLIBD)/libss.a"
ss_lib=-lss
])
dnl
dnl This rule tells KRB5_LIBRARIES to include the dyn library.
dnl
dyn_deplib=''
dyn_lib=''
define(USE_DYN_LIBRARY,[
dyn_deplib="\[$](TOPLIBD)/libdyn.a"
dyn_lib=-ldyn
])
dnl
dnl This rule tells KRB5_LIBRARIES to include the db library.
dnl
db_deplib=''
db_lib=''
define(USE_DB_LIBRARY,[
db_deplib="\[$](TOPLIBD)/libdb.a"
db_lib="\[$](TOPLIBD)/libdb.a"
])
dnl
dnl This rule generates library lists for programs.
dnl
define(KRB5_LIBRARIES,[
dnl
dnl under solaris, if we use compile() and step(), we need -lgen
save_LIBS="$LIBS"
LIBS=-lgen
dnl this will fail if there's no compile/step in -lgen, or if there's
dnl no -lgen.  This is fine.
AC_CHECK_FUNCS(compile step)
[if test "$ac_cv_func_compile" = yes ; then
	LIBS="$save_LIBS -lgen"
else
	LIBS="$save_LIBS"
fi]
dnl this is ugly, but it wouldn't be necessary if krb5 didn't abuse
dnl configure so badly
SRVDEPLIBS="\[$](DEPLOCAL_LIBRARIES) $kadmsrv_deplib $gssrpc_deplib $gssapi_deplib $kdb5_deplib $kutil_deplib \[$](TOPLIBD)/libkrb5.a $krb4_deplib \[$](TOPLIBD)/libcrypto.a $ss_deplib $dyn_deplib $db_deplib \[$](TOPLIBD)/libcom_err.a"
SRVLIBS="\[$](LOCAL_LIBRARIES) $kadmsrv_lib $gssrpc_lib $gssapi_lib $kdb5_lib $kutil_lib $krb4_lib -lkrb5 -lcrypto $ss_lib $dyn_lib $db_lib -lcom_err $LIBS"
CLNTDEPLIBS="\[$](DEPLOCAL_LIBRARIES) $kadmclnt_deplib $gssrpc_deplib $gssapi_deplib $kdb5_deplib $kutil_deplib \[$](TOPLIBD)/libkrb5.a $krb4_deplib \[$](TOPLIBD)/libcrypto.a $ss_deplib $dyn_deplib $db_deplib \[$](TOPLIBD)/libcom_err.a"
CLNTLIBS="\[$](LOCAL_LIBRARIES) $kadmclnt_lib $gssrpc_lib $gssapi_lib $kdb5_lib $kutil_lib $krb4_lib -lkrb5 -lcrypto $ss_lib $dyn_lib $db_lib -lcom_err $LIBS"
DEPLIBS="\[$](DEPLOCAL_LIBRARIES) $kadmclnt_deplib $kadmsrv_deplib $gssrpc_deplib $gssapi_deplib $kdb5_deplib $kutil_deplib \[$](TOPLIBD)/libkrb5.a $krb4_deplib \[$](TOPLIBD)/libcrypto.a $ss_deplib $dyn_deplib $db_deplib \[$](TOPLIBD)/libcom_err.a"
LIBS="\[$](LOCAL_LIBRARIES) $kadmclnt_lib $kadmsrv_lib $gssrpc_lib $gssapi_lib $kdb5_lib $kutil_lib $krb4_lib -lkrb5 -lcrypto $ss_lib $dyn_lib $db_lib -lcom_err $LIBS"
LDFLAGS="$LDFLAGS -L\$(TOPLIBD)"
AC_SUBST(LDFLAGS)
AC_SUBST(LDARGS)
AC_SUBST(DEPLIBS)
AC_SUBST(SRVDEPLIBS)
AC_SUBST(SRVLIBS)
AC_SUBST(CLNTDEPLIBS)
AC_SUBST(CLNTLIBS)])
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
		LDARGS="$LDARGS ${krb5_cv_shlibs_dirhead}\$(KRB5_SHLIBDIR)"
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
dnl
dnl
dnl Check for prototype support - used by application not including k5-int.h
dnl
define(KRB5_CHECK_PROTOS,[
AC_MSG_CHECKING([prototype support])
AC_CACHE_VAL(krb5_cv_has_prototypes,
[AC_TRY_COMPILE(
[int x(double y, int z);], [],
krb5_cv_has_prototypes=yes, krb5_cv_has_prototypes=no)])
AC_MSG_RESULT($krb5_cv_has_prototypes)
if test $krb5_cv_has_prototypes = no; then
AC_DEFINE(KRB5_NO_PROTOTYPES)
else
AC_DEFINE(KRB5_PROVIDE_PROTOTYPES)
fi
dnl *never* set NARROW_PROTOTYPES
])dnl
dnl
dnl Check if stdarg or varargs is available *and compiles*; prefer stdarg.
dnl (This was sent to djm for incorporation into autoconf 3/12/1996.  KR)
dnl
AC_DEFUN(AC_HEADER_STDARG, [

AC_MSG_CHECKING([for stdarg.h])
AC_CACHE_VAL(ac_cv_header_stdarg_h,
[AC_TRY_COMPILE([#include <stdarg.h>], [
  } /* ac_try_compile will have started a function body */
  int aoeu (char *format, ...) {
    va_list v;
    int i;
    va_start (v, format);
    i = va_arg (v, int);
    va_end (v);
],ac_cv_header_stdarg_h=yes,ac_cv_header_stdarg_h=no)])dnl
AC_MSG_RESULT($ac_cv_header_stdarg_h)
if test $ac_cv_header_stdarg_h = yes; then
  AC_DEFINE(HAVE_STDARG_H)
else

AC_MSG_CHECKING([for varargs.h])
AC_CACHE_VAL(ac_cv_header_varargs_h,
[AC_TRY_COMPILE([#include <varargs.h>],[
  } /* ac_try_compile will have started a function body */
  int aoeu (va_alist) va_dcl {
    va_list v;
    int i;
    va_start (v);
    i = va_arg (v, int);
    va_end (v);
],ac_cv_header_varargs_h=yes,ac_cv_header_varargs_h=no)])dnl
AC_MSG_RESULT($ac_cv_header_varargs_h)
if test $ac_cv_header_varargs_h = yes; then
  AC_DEFINE(HAVE_VARARGS_H)
else
  AC_MSG_ERROR(Neither stdarg nor varargs compile?)
fi

fi dnl stdarg test failure

])dnl

dnl
dnl AC_KRB5_TCL - determine if the TCL library is present on system
dnl
AC_DEFUN(AC_KRB5_TCL,[
TCL_INCLUDES=
TCL_LIBPATH=
TCL_RPATH=
TCL_LIBS=
TCL_WITH=
AC_ARG_WITH(tcl,
[  --with-tcl=path         where Tcl resides],
	TCL_WITH=$withval
	if test "$withval" != yes -a "$withval" != no ; then
		TCL_INCLUDES=-I$withval/include
		TCL_LIBPATH=-L$withval/lib
		TCL_RPATH=:$withval/lib
	fi)
if test "$TCL_WITH" != no ; then
	AC_CHECK_LIB(dl, dlopen, DL_LIB=-ldl)
	AC_CHECK_LIB(ld, main, DL_LIB=-lld)
	krb5_save_CPPFLAGS="$CPPFLAGS"
	krb5_save_LDFLAGS="$LDFLAGS"
	CPPFLAGS="$TCL_INCLUDES $CPPFLAGS"
	LDFLAGS="$TCL_LIBPATH $LDFLAGS"
	AC_CHECK_HEADER(tcl.h,dnl
		AC_CHECK_LIB(tcl7.5, Tcl_CreateCommand, 
			TCL_LIBS="$TCL_LIBS -ltcl7.5 -lm $DL_LIB",
			AC_CHECK_LIB(tcl, Tcl_CreateCommand, 
				TCL_LIBS="$TCL_LIBS -ltcl -lm $DL_LIB",
				AC_MSG_WARN("tcl.h found but not library"),
				-lm $DL_LIB),
			-lm $DL_LIB),dnl tcl.h not found
	AC_MSG_WARN(Could not find Tcl which is needed for the kadm5 tests)
	TCL_LIBS=)
	CPPFLAGS="$krb5_save_CPPFLAGS"
	LDFLAGS="$krb5_save_LDFLAGS"
	AC_SUBST(TCL_INCLUDES)
	AC_SUBST(TCL_LIBS)
	AC_SUBST(TCL_LIBPATH)
	AC_SUBST(TCL_RPATH)
else
	AC_MSG_RESULT("Not looking for Tcl library")
fi
])dnl

dnl
dnl KRB5_BUILD_LIBRARY
dnl
dnl Pull in the necessary stuff to create the libraries.

AC_DEFUN(KRB5_BUILD_LIBRARY,
[AC_REQUIRE([KRB5_LIB_AUX])
AC_REQUIRE([AC_LN_S])
AC_REQUIRE([AC_PROG_RANLIB])
AC_CHECK_PROG(AR, ar, ar, false)
# add frag for building libraries
krb5_append_frags=$ac_config_fragdir/lib.in:$krb5_append_frags
# null out SHLIB_EXPFLAGS because we lack any dependencies
SHLIB_EXPFLAGS=
AC_SUBST(LIBLIST)
AC_SUBST(LIBLINKS)
AC_SUBST(LDCOMBINE)
AC_SUBST(LDCOMBINE_TAIL)
AC_SUBST(SHLIB_EXPFLAGS)
AC_SUBST(STLIBEXT)
AC_SUBST(SHLIBEXT)
AC_SUBST(SHLIBVEXT)
AC_SUBST(PFLIBEXT)
AC_SUBST(LIBINSTLIST)])

dnl
dnl KRB5_BUILD_LIBRARY_STATIC
dnl
dnl Force static library build.

AC_DEFUN(KRB5_BUILD_LIBRARY_STATIC,
[krb5_force_static=yes
KRB5_BUILD_LIBRARY])

dnl
dnl KRB5_BUILD_LIBRARY_WITH_DEPS
dnl
dnl Like KRB5_BUILD_LIBRARY, but adds in explicit dependencies in the
dnl generated shared library.

AC_DEFUN(KRB5_BUILD_LIBRARY_WITH_DEPS,
[AC_REQUIRE([KRB5_LIB_AUX])
AC_REQUIRE([AC_LN_S])
AC_REQUIRE([AC_PROG_RANLIB])
AC_CHECK_PROG(AR, ar, ar, false)
# add frag for building libraries
krb5_append_frags=$ac_config_fragdir/lib.in:$krb5_append_frags
AC_SUBST(LIBLIST)
AC_SUBST(LIBLINKS)
AC_SUBST(LDCOMBINE)
AC_SUBST(LDCOMBINE_TAIL)
AC_SUBST(SHLIB_EXPFLAGS)
AC_SUBST(STLIBEXT)
AC_SUBST(SHLIBEXT)
AC_SUBST(SHLIBVEXT)
AC_SUBST(PFLIBEXT)
AC_SUBST(LIBINSTLIST)])

dnl
dnl KRB5_BUILD_LIBOBJS
dnl
dnl Pull in the necessary stuff to build library objects.

AC_DEFUN(KRB5_BUILD_LIBOBJS,
[AC_REQUIRE([KRB5_LIB_AUX])
# add frag for building library objects
krb5_append_frags=$ac_config_fragdir/libobj.in:$krb5_append_frags
AC_SUBST(OBJLISTS)
AC_SUBST(STOBJEXT)
AC_SUBST(SHOBJEXT)
AC_SUBST(PFOBJEXT)
AC_SUBST(PICFLAGS)
AC_SUBST(PROFFLAGS)])

dnl
dnl KRB5_BUILD_PROGRAM
dnl
dnl Set variables to build a program.

AC_DEFUN(KRB5_BUILD_PROGRAM,
[AC_REQUIRE([KRB5_LIB_AUX])
AC_CHECK_LIB(gen, compile, GEN_LIB=-lgen, GEN_LIB=)
AC_SUBST(GEN_LIB)
AC_SUBST(CC_LINK)
AC_SUBST(DEPLIBEXT)])

dnl
dnl KRB5_RUN_FLAGS
dnl
dnl Set up environment for running dynamic execuatbles out of build tree

AC_DEFUN(KRB5_RUN_FLAGS,
[AC_REQUIRE([KRB5_LIB_AUX])
KRB5_RUN_ENV="$RUN_ENV"
AC_SUBST(KRB5_RUN_ENV)])

dnl
dnl KRB5_LIB_AUX
dnl
dnl Parse configure options related to library building.

AC_DEFUN(KRB5_LIB_AUX,
[AC_REQUIRE([KRB5_LIB_PARAMS])
# Check whether to build static libraries.
AC_ARG_ENABLE([static],
[  --disable-static        don't build static libraries], ,
[enableval=yes])

if test "$enableval" = no && test "$krb5_force_static" != yes; then
	AC_MSG_RESULT([Disabling static libraries.])
	LIBLINKS=
	LIBLIST=
	OBJLISTS=
else
	LIBLIST='lib$(LIB)$(STLIBEXT)'
	LIBLINKS='$(TOPLIBD)/lib$(LIB)$(STLIBEXT)'
	OBJLISTS=OBJS.ST
	LIBINSTLIST=install-static
	DEPLIBEXT=$STLIBEXT
fi

# Check whether to build shared libraries.
AC_ARG_ENABLE([shared],
[  --enable-shared         build shared libraries],
[if test "$enableval" = yes && test "$krb5_force_static" != yes; then
	case "$SHLIBEXT" in
	.so-nobuild)
		AC_MSG_WARN([shared libraries not supported on this architecture])
		RUN_ENV=
		CC_LINK="$CC_LINK_STATIC"
		;;
	*)
		AC_MSG_RESULT([Enabling shared libraries.])
		LIBLIST="$LIBLIST "'lib$(LIB)$(SHLIBEXT)'
		LIBLINKS="$LIBLINKS "'$(TOPLIBD)/lib$(LIB)$(SHLIBEXT) $(TOPLIBD)/lib$(LIB)$(SHLIBVEXT)'
		OBJLISTS="$OBJLISTS OBJS.SH"
		LIBINSTLIST="$LIBINSTLIST install-shared"
		DEPLIBEXT=$SHLIBEXT
		CC_LINK="$CC_LINK_SHARED"
		;;
	esac
else
	RUN_ENV=
	CC_LINK="$CC_LINK_STATIC"
fi],
	RUN_ENV=
	CC_LINK="$CC_LINK_STATIC"
)dnl

if test -z "$LIBLIST"; then
	AC_MSG_ERROR([must enable one of shared or static libraries])
fi

# Check whether to build profiled libraries.
AC_ARG_ENABLE([profiled],
[  --enable-profiled       build profiled libraries],
[if test "$enableval" = yes; then
	case $PFLIBEXT in
	.po-nobuild)
		AC_MSG_RESULT([Profiled libraries not supported on this architecture.])
		;;
	*)
		AC_MSG_RESULT([Enabling profiled libraries.])
		LIBLIST="$LIBLIST "'lib$(LIB)$(PFLIBEXT)'
		LIBLINKS="$LIBLINKS "'$(TOPLIBD)/lib$(LIB)$(PFLIBEXT)'
		OBJLISTS="$OBJLISTS OBJS.PF"
		LIBINSTLIST="$LIBINSTLIST install-profiled"
		;;
	esac
fi])])

dnl
dnl KRB5_LIB_PARAMS
dnl
dnl Determine parameters related to libraries, e.g. various extensions.

AC_DEFUN(KRB5_LIB_PARAMS,
[AC_CHECKING([host system type])
AC_CACHE_VAL(krb5_cv_host,
[AC_CANONICAL_HOST
krb5_cv_host=$host])
AC_MSG_RESULT($krb5_cv_host)
AC_REQUIRE([AC_PROG_CC])
#
# Set up some defaults.
#
STLIBEXT=.a
# Default to being unable to build shared libraries.
SHLIBEXT=.so-nobuild
SHLIBVEXT=.so.v-nobuild
# Most systems support profiled libraries.
PFLIBEXT=_p.a

STOBJEXT=.o
SHOBJEXT=.so
PFOBJEXT=.po
# Default for systems w/o shared libraries
CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'

# Set up architecture-specific variables.
case $krb5_cv_host in
alpha-dec-osf*)
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.so
	# Alpha OSF/1 doesn't need separate PIC objects
	SHOBJEXT=.o
	LDCOMBINE='ld -shared -expect_unresolved \* -update_registry $(BUILDTOP)/so_locations'
	SHLIB_EXPFLAGS='-rpath $(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	PROFFLAGS=-pg
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Wl,-rpath -Wl,$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	# $(PROG_RPATH) is here to handle things like a shared tcl library
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`:$(PROG_RPATH):/usr/shlib:/usr/ccs/lib:/usr/lib/cmplrs/cc:/usr/lib:/usr/local/lib; export LD_LIBRARY_PATH; _RLD_ROOT=/dev/dummy/d; export _RLD_ROOT;'
	;;
mips-sgi-irix*)
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.so
	SHOBJEXT=.o
	LDCOMBINE='ld -shared -ignore_unresolved -update_registry $(BUILDTOP)/so_locations'
	SHLIB_EXPFLAGS='-rpath $(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	# no gprof for Irix...
	PROFFLAGS=-p
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Wl,-rpath -Wl,$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	;;
*-*-netbsd*)
	PICFLAGS=-fpic
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.so
	LDCOMBINE='ld -Bshareable'
	SHLIB_EXPFLAGS='-R$(SHLIB_RDIRS) $(SHLIB_DIRS)'
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -R$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	PROFFLAGS=-pg
	;;
*-*-solaris*)
	if test "$GCC" = yes; then
		PICFLAGS=-fpic
		LDCOMBINE='$(CC) -shared'
	else
		PICFLAGS=-Kpic
		# Solaris cc doesn't default to stuffing the SONAME field...
		LDCOMBINE='$(CC) -dy -G -z text -h lib$(LIB)$(SHLIBEXT).$(LIBMAJOR).$(LIBMINOR)'
	fi
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.so
	SHLIB_EXPFLAGS='-R$(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	PROFFLAGS=-pg
	CC_LINK_SHARED='$(PURE) $(CC) $(PROG_LIBPATH) -R$(PROG_RPATH)'
	CC_LINK_STATIC='$(PURE) $(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	;;
*-*-sunos*)
	PICFLAGS=-fpic
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.so
	# The following grossness is to prevent relative paths from
	# creeping into the RPATH of an executable or library built
	# under SunOS; the explicit setting of LD_LIBRARY_PATH does
	# does not make it into the output file, while directories
	# passed by "-Ldirname" do.
	LDCOMBINE='LD_LIBRARY_PATH=`echo $(SHLIB_DIRS) | sed -e "s/-L//g" -e "s/ /:/g"` ld -dp -assert pure-text'
	SHLIB_EXPFLAGS='-L$(SHLIB_RDIRS) $(SHLIB_EXPLIBS)'
	PROFFLAGS=-pg
	CC_LINK_SHARED='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"` $(PURE) $(CC) -L$(PROG_RPATH)'
	CC_LINK_STATIC='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g` $(PURE) $(CC)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	;;
*-*-linux*)
	PICFLAGS=-fPIC
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.so
	# Linux ld doesn't default to stuffing the SONAME field...
	# Use objdump -x to examine the fields of the library
	LDCOMBINE='ld -shared -h lib$(LIB)$(SHLIBEXT).$(LIBMAJOR).$(LIBMINOR)'
	SHLIB_EXPFLAGS='-R$(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	PROFFLAGS=-pg
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Wl,-rpath -Wl,$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	;;
esac])

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
krb5_pre_in=$ac_config_fragdir/pre.in
krb5_post_in=$ac_config_fragdir/post.in
krb5_prepend_frags=$krb5_pre_in
krb5_append_frags=$krb5_post_in
if test -d "$srcdir/$ac_config_fragdir"; then
  AC_CONFIG_AUX_DIR($ac_config_fragdir)
else
  AC_MSG_ERROR([can not find config/ directory in $ac_reltopdir])
fi
])dnl
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
WITH_HESIOD dnl
KRB_INCLUDE dnl
AC_ARG_PROGRAM dnl
dnl
dnl This selects the correct autoconf file; either the one in our source tree,
dnl or the one found in the user's path.  $srcdir may be relative, and if so,
dnl it's relative to the directory of the configure script.  Since the 
dnl automatic makefile rules to rerun autoconf cd into that directory, the
dnl right thing happens.
dnl
if test -f $srcdir/$ac_reltopdir/util/autoconf/autoconf ; then
	AUTOCONF=$ac_reltopdir/util/autoconf/autoconf
else
	AUTOCONF=autoconf
fi
AC_SUBST(AUTOCONF)
dnl
dnl This identifies the top of the source tree relative to the directory 
dnl in which the configure file lives.
dnl
CONFIG_RELTOPDIR=$ac_reltopdir
AC_SUBST(CONFIG_RELTOPDIR)
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
dnl Generic File existence tests
dnl 
dnl K5_AC_CHECK_FILE(FILE, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl
AC_DEFUN(K5_AC_CHECK_FILE,
[AC_REQUIRE([AC_PROG_CC])
dnl Do the transliteration at runtime so arg 1 can be a shell variable.
ac_safe=`echo "$1" | sed 'y%./+-%__p_%'`
AC_MSG_CHECKING([for $1])
AC_CACHE_VAL(ac_cv_file_$ac_safe,
[if test "$cross_compiling" = yes; then
  errprint(__file__:__line__: warning: Cannot check for file existence when cross compiling
)dnl
  AC_MSG_ERROR(Cannot check for file existence when cross compiling)
else
  if test -r $1; then
    eval "ac_cv_file_$ac_safe=yes"
  else
    eval "ac_cv_file_$ac_safe=no"
  fi
fi])dnl
if eval "test \"`echo '$ac_cv_file_'$ac_safe`\" = yes"; then
  AC_MSG_RESULT(yes)
  ifelse([$2], , :, [$2])
else
  AC_MSG_RESULT(no)
ifelse([$3], , , [$3
np])dnl
fi
])
dnl
dnl K5_AC_CHECK_FILES(FILE... [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl
AC_DEFUN(K5_AC_CHECK_FILES,
[for ac_file in $1
do
K5_AC_CHECK_FILE($ac_file,
[changequote(, )dnl
  ac_tr_file=HAVE`echo $ac_file | sed 'y%abcdefghijklmnopqrstuvwxyz./-%ABCDEFGHIJKLMNOPQRSTUVWXYZ___%'`
changequote([, ])dnl
  AC_DEFINE_UNQUOTED($ac_tr_file) $2], $3)dnl
done
])
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
dnl K5_GEN_MAKEFILE([dir, [frags]])
dnl
define(K5_GEN_MAKEFILE,[dnl
ifelse($1, , x=., x="$1")
appendlist=''
ifelse($2, , ,[dnl
for i in $2
do
	appendlist=$appendlist:$ac_config_fragdir/$i.in
done])
krb5_output_list="$krb5_output_list $x/Makefile:$krb5_pre_in:$x/Makefile.in$appendlist:$krb5_post_in"])dnl
dnl
dnl K5_GEN_FILE( <ac_output arguments> )
dnl
define(K5_GEN_FILE,[krb5_output_list="$krb5_output_list $1"])dnl
dnl
dnl K5_AC_OUTPUT
dnl
define(K5_AC_OUTPUT,[AC_OUTPUT($krb5_output_list)])dnl
dnl
dnl K5_OUTPUT_FILES
dnl
dnl This is for compatibility purposes, and is deprecated...
dnl
define(K5_OUTPUT_FILES,[K5_AC_OUTPUT])dnl
dnl
dnl V5_OUTPUT_MAKEFILE
dnl
define(V5_AC_OUTPUT_MAKEFILE,
[ifelse($1, , ac_v5_makefile_dirs=., ac_v5_makefile_dirs="$1")
ifelse($2, , filelist="", filelist="$2")
for x in $ac_v5_makefile_dirs; do
  filelist="$filelist $x/Makefile:$krb5_prepend_frags:$x/Makefile.in:$krb5_append_frags"
done
AC_OUTPUT($filelist)])dnl
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
[AC_LIBRARY_NET]
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
dnl KRB5_AC_REGEX_FUNCS --- check for different regular expression 
dnl				support functions
dnl
AC_DEFUN(KRB5_AC_REGEX_FUNCS,[
AC_CHECK_FUNCS(re_comp re_exec regexec)
dnl
dnl regcomp is present but non-functional on Solaris 2.4
dnl
AC_C_CROSS
AC_MSG_CHECKING(for working regcomp)
AC_CACHE_VAL(ac_cv_func_regcomp,[
AC_TRY_RUN([
#include <sys/types.h>
#include <regex.h>
regex_t x; regmatch_t m;
int main() { return regcomp(&x,"pat.*",0) || regexec(&x,"pattern",1,&m,0); }
], ac_cv_func_regcomp=yes, ac_cv_func_regcomp=no)])
AC_MSG_RESULT($ac_cv_func_regcomp)
test $ac_cv_func_regcomp = yes && AC_DEFINE(HAVE_REGCOMP)
dnl
dnl Check for the compile and step functions
dnl
save_LIBS="$LIBS"
LIBS=-lgen
dnl this will fail if there's no compile/step in -lgen, or if there's
dnl no -lgen.  This is fine.
AC_CHECK_FUNCS(compile step)
LIBS="$save_LIBS"
dnl
dnl Set GEN_LIB if necessary 
dnl
AC_CHECK_LIB(gen, compile, GEN_LIB=-lgen, GEN_LIB=)
AC_SUBST(GEN_LIB)
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
	tcl_header=no
	AC_CHECK_HEADER(tcl.h,AC_DEFINE(HAVE_TCL_H) tcl_header=yes)
	if test $tcl_header=no; then
	   AC_CHECK_HEADER(tcl/tcl.h,AC_DEFINE(HAVE_TCL_TCL_H) tcl_header=yes)
	fi

	if test $tcl_header = yes ; then
		tcl_lib=no

		if test $tcl_lib = no; then
			AC_CHECK_LIB(tcl8.0, Tcl_CreateCommand, 
				TCL_LIBS="$TCL_LIBS -ltcl8.0 -lm $DL_LIB" 
				tcl_lib=yes,,-lm $DL_LIB)
		fi
		if test $tcl_lib = no; then
			AC_CHECK_LIB(tcl7.6, Tcl_CreateCommand, 
				TCL_LIBS="$TCL_LIBS -ltcl7.6 -lm $DL_LIB" 
				tcl_lib=yes,,-lm $DL_LIB)
		fi
		if test $tcl_lib = no; then
			AC_CHECK_LIB(tcl7.5, Tcl_CreateCommand, 
				TCL_LIBS="$TCL_LIBS -ltcl7.5 -lm $DL_LIB"
				tcl_lib=yes,,-lm $DL_LIB)

		fi
		if test $tcl_lib = no ; then
			AC_CHECK_LIB(tcl, Tcl_CreateCommand, 
				TCL_LIBS="$TCL_LIBS -ltcl -lm $DL_LIB"
				tcl_lib=yes,,-lm $DL_LIB)

		fi
		if test $tcl_lib = no ; then		
			AC_MSG_WARN("tcl.h found but not library")
		fi
	else
		AC_MSG_WARN(Could not find Tcl which is needed for the kadm5 tests)
		TCL_LIBS=
	fi
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
dnl WITH_HESIOD
dnl
AC_DEFUN(WITH_HESIOD,
[AC_ARG_WITH(hesiod, [  --with-hesiod[=path]    compile with hesiod support],
	hesiod=$with_hesiod, with_hesiod=no)
if test "$with_hesiod" != "no"; then
	HESIOD_DEFS=-DHESIOD
	AC_CHECK_LIB(resolv, res_send, res_lib=-lresolv)
	if test "$hesiod" != "yes"; then
		HESIOD_LIBS="-L${hesiod}/lib -lhesiod $res_lib"
	else
		HESIOD_LIBS="-lhesiod $res_lib"
	fi
else
	HESIOD_DEFS=
	HESIOD_LIBS=
fi
AC_SUBST(HESIOD_DEFS)
AC_SUBST(HESIOD_LIBS)])


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
AC_SUBST(SHLIBSEXT)
AC_SUBST(PFLIBEXT)
AC_SUBST(LIBINSTLIST)])

dnl
dnl KRB5_BUILD_LIBRARY_STATIC
dnl
dnl Force static library build.

define(KRB5_BUILD_LIBRARY_STATIC,
dnl Use define rather than AC_DEFUN to avoid ordering problems.
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
AC_SUBST(SHLIBSEXT)
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
[if test "$enableval" = yes; then
	case "$SHLIBEXT" in
	.so-nobuild)
		AC_MSG_WARN([shared libraries not supported on this architecture])
		RUN_ENV=
		CC_LINK="$CC_LINK_STATIC"
		;;
	*)
		# set this now because some logic below may reset SHLIBEXT
		DEPLIBEXT=$SHLIBEXT
		if test "$krb5_force_static" = "yes"; then
			AC_MSG_RESULT([Forcing static libraries.])
			# avoid duplicate rules generation for AIX and such
			SHLIBEXT=.so-nobuild
		else
			AC_MSG_RESULT([Enabling shared libraries.])
			LIBLIST="$LIBLIST "'lib$(LIB)$(SHLIBEXT)'
			LIBLINKS="$LIBLINKS "'$(TOPLIBD)/lib$(LIB)$(SHLIBEXT) $(TOPLIBD)/lib$(LIB)$(SHLIBVEXT)'
			case "$SHLIBSEXT" in
			.so.s-nobuild)
				LIBINSTLIST="$LIBINSTLIST install-shared"
				;;
			*)
				LIBLIST="$LIBLIST "'lib$(LIB)$(SHLIBSEXT)'
				LIBLINKS="$LIBLINKS "'$(TOPLIBD)/lib$(LIB)$(SHLIBSEXT)'
				LIBINSTLIST="$LIBINSTLIST install-shlib-soname"
				;;
			esac
			OBJLISTS="$OBJLISTS OBJS.SH"
		fi
		CC_LINK="$CC_LINK_SHARED"
		if test "$STLIBEXT" = "$SHLIBEXT" ; then
		  STLIBEXT=".a-no-build"
		  LIBINSTLIST="install-shared" #don't install static
		fi
		;;
	esac
else
	RUN_ENV=
	CC_LINK="$CC_LINK_STATIC"
	SHLIBEXT=.so-nobuild
	SHLIBVEXT=.so.v-nobuild
	SHLIBSEXT=.so.s-nobuild
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
SHLIBSEXT=.so.s-nobuild
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
	SHLIBSEXT='.so.$(LIBMAJOR)'
	SHLIBEXT=.so
	# Alpha OSF/1 doesn't need separate PIC objects
	SHOBJEXT=.o
	LDCOMBINE='ld -shared -expect_unresolved \* -update_registry $(BUILDTOP)/so_locations -soname lib$(LIB)$(SHLIBSEXT)'
	SHLIB_EXPFLAGS='-rpath $(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	PROFFLAGS=-pg
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Wl,-rpath -Wl,$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	# $(PROG_RPATH) is here to handle things like a shared tcl library
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`:$(PROG_RPATH):/usr/shlib:/usr/ccs/lib:/usr/lib/cmplrs/cc:/usr/lib:/usr/local/lib; export LD_LIBRARY_PATH; _RLD_ROOT=/dev/dummy/d; export _RLD_ROOT;'
	;;

# HPUX untested...
# 
# Note: "-Wl,+s" when building executables enables the use of the
# SHLIB_PATH environment variable for finding shared libraries 
# in non-standard directories.  If a non-standard search-path for
#  shared libraries is compiled into the executable (using 
# -Wl,+b,$KRB5_SHLIBDIR), then the order of "-Wl,+b,..." and "-Wl,+s" 
# on the commandline of the linker will determine which path
# (compiled-in or SHLIB_PATH) will be searched first.
#
*-*-hpux*)
	PICFLAGS=+z
	SHLIBEXT=.sl
	SHLIBVEXT='.sl.$(LIBMAJOR).$(LIBMINOR)'
	SHLIB_EXPFLAGS='+b $(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	LDCOMBINE='ld -b'
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Wl,+s -Wl,+b,$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='SHLIB_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export SHLIB_PATH;'
	;;

mips-sgi-irix6.3)	# This is a Kludge; see below
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBSEXT='.so.$(LIBMAJOR)'
	SHLIBEXT=.so
	SHOBJEXT=.o
	# Kludge follows: (gcc makes n32 object files but ld expects o32, so we reeducate ld)
	if test "$krb5_cv_prog_gcc" = yes; then
		LDCOMBINE='ld -n32 -shared -ignore_unresolved -update_registry $(BUILDTOP)/so_locations -soname lib$(LIB)$(SHLIBSEXT)'
	else
		LDCOMBINE='ld -shared -ignore_unresolved -update_registry $(BUILDTOP)/so_locations -soname lib$(LIB)$(SHLIBSEXT)'
	fi
	SHLIB_EXPFLAGS='-rpath $(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	# no gprof for Irix...
	PROFFLAGS=-p
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Wl,-rpath -Wl,$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	;;

mips-sgi-irix*)
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBSEXT='.so.$(LIBMAJOR)'
	SHLIBEXT=.so
	SHOBJEXT=.o
	LDCOMBINE='ld -shared -ignore_unresolved -update_registry $(BUILDTOP)/so_locations -soname lib$(LIB)$(SHLIBSEXT)'
	SHLIB_EXPFLAGS='-rpath $(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	# no gprof for Irix...
	PROFFLAGS=-p
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Wl,-rpath -Wl,$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	;;

# untested...
mips-sni-sysv4)
	if test "$krb5_cv_prog_gcc" = yes; then
		PICFLAGS=-fpic
		LDCOMBINE='$(CC) -G -Wl,-h -Wl,lib$(LIB)$(SHLIBSEXT)'
	else
		PICFLAGS=-Kpic
		LDCOMBINE='$(CC) -G -h lib$(LIB)$(SHLIBSEXT)'
	fi
	SHLIB_EXPFLAGS='-R$(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	SHLIBEXT=.so
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBSEXT='.so.$(LIBMAJOR)'
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -R$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	PROFFLAGS=-pg
	;;

mips-*-netbsd*)
	PICFLAGS=-fPIC
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBSEXT='.so.$(LIBMAJOR)'
	SHLIBEXT=.so
	LDCOMBINE='ld -shared -soname lib$(LIB)$(SHLIBSEXT)'
	SHLIB_EXPFLAGS='-R$(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Wl,-rpath -Wl,$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	PROFFLAGS=-pg
	;;

*-*-netbsd*)
	PICFLAGS=-fpic
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.so
	LDCOMBINE='ld -Bshareable'
	SHLIB_EXPFLAGS='-R$(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -R$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	PROFFLAGS=-pg
	;;

*-*-freebsd*)
	PICFLAGS=-fpic
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.so
	LDCOMBINE='ld -Bshareable'
	SHLIB_EXPFLAGS='-R$(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -R$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	PROFFLAGS=-pg
	;;

*-*-openbsd*)
	PICFLAGS=-fpic
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.so
	LDCOMBINE='ld -Bshareable'
	SHLIB_EXPFLAGS='-R$(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -R$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	PROFFLAGS=-pg
	;;

*-*-solaris*)
	if test "$krb5_cv_prog_gcc" = yes; then
		PICFLAGS=-fpic
		LDCOMBINE='$(CC) -shared -h lib$(LIB)$(SHLIBSEXT)'
	else
		PICFLAGS=-Kpic
		# Solaris cc doesn't default to stuffing the SONAME field...
		LDCOMBINE='$(CC) -dy -G -z text -h lib$(LIB)$(SHLIBSEXT)'
	fi
	SHLIBVEXT='.so.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBSEXT='.so.$(LIBMAJOR)'
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
	SHLIBSEXT='.so.$(LIBMAJOR)'
	SHLIBEXT=.so
	# Linux ld doesn't default to stuffing the SONAME field...
	# Use objdump -x to examine the fields of the library
	LDCOMBINE='ld -shared -h lib$(LIB)$(SHLIBSEXT)'
	SHLIB_EXPFLAGS='-R$(SHLIB_RDIRS) $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	PROFFLAGS=-pg
	CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Wl,-rpath -Wl,$(PROG_RPATH)'
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	RUN_ENV='LD_LIBRARY_PATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`; export LD_LIBRARY_PATH;'
	;;

*-*-aix*)
	SHLIBVEXT='.a.$(LIBMAJOR).$(LIBMINOR)'
	SHLIBEXT=.a
	# AIX doesn't need separate PIC objects
	SHOBJEXT=.o
	LDCOMBINE='$(BUILDTOP)/util/makeshlib $(LIBMAJOR).$(LIBMINOR)'
	SHLIB_EXPFLAGS='  $(SHLIB_DIRS) $(SHLIB_EXPLIBS)'
	PROFFLAGS=-pg
	if test "$krb5_cv_prog_gcc" = "yes" ; then
 	  CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -Xlinker -bex4:$(BUILDTOP)/util/aix.bincmds '
	else
	  CC_LINK_SHARED='$(CC) $(PROG_LIBPATH) -bex4:$(BUILDTOP)/util/aix.bincmds '
	fi
	CC_LINK_STATIC='$(CC) $(PROG_LIBPATH)'
	# $(PROG_RPATH) is here to handle things like a shared tcl library
	RUN_ENV='LIBPATH=`echo $(PROG_LIBPATH) | sed -e "s/-L//g" -e "s/ /:/g"`:$(PROG_RPATH):/usr/lib:/usr/local/lib; export LIBPATH; '

esac])
dnl
dnl The following was written by jhawk@mit.edu
dnl
dnl AC_LIBRARY_NET: Id: net.m4,v 1.4 1997/10/25 20:49:53 jhawk Exp 
dnl
dnl This test is for network applications that need socket() and
dnl gethostbyname() -ish functions.  Under Solaris, those applications need to
dnl link with "-lsocket -lnsl".  Under IRIX, they should *not* link with
dnl "-lsocket" because libsocket.a breaks a number of things (for instance:
dnl gethostbyname() under IRIX 5.2, and snoop sockets under most versions of
dnl IRIX).
dnl 
dnl Unfortunately, many application developers are not aware of this, and
dnl mistakenly write tests that cause -lsocket to be used under IRIX.  It is
dnl also easy to write tests that cause -lnsl to be used under operating
dnl systems where neither are necessary (or useful), such as SunOS 4.1.4, which
dnl uses -lnsl for TLI.
dnl 
dnl This test exists so that every application developer does not test this in
dnl a different, and subtly broken fashion.
dnl 
dnl It has been argued that this test should be broken up into two seperate
dnl tests, one for the resolver libraries, and one for the libraries necessary
dnl for using Sockets API. Unfortunately, the two are carefully intertwined and
dnl allowing the autoconf user to use them independantly potentially results in
dnl unfortunate ordering dependancies -- as such, such component macros would
dnl have to carefully use indirection and be aware if the other components were
dnl executed. Since other autoconf macros do not go to this trouble, and almost
dnl no applications use sockets without the resolver, this complexity has not
dnl been implemented.
dnl
dnl The check for libresolv is in case you are attempting to link statically
dnl and happen to have a libresolv.a lying around (and no libnsl.a).
dnl
AC_DEFUN(AC_LIBRARY_NET, [
   # Most operating systems have gethostbyname() in the default searched
   # libraries (i.e. libc):
   AC_CHECK_FUNC(gethostbyname, ,
     # Some OSes (eg. Solaris) place it in libnsl:
     AC_CHECK_LIB(nsl, gethostbyname, , 
       # Some strange OSes (SINIX) have it in libsocket:
       AC_CHECK_LIB(socket, gethostbyname, ,
          # Unfortunately libsocket sometimes depends on libnsl.
          # AC_CHECK_LIB's API is essentially broken so the following
          # ugliness is necessary:
          AC_CHECK_LIB(socket, gethostbyname,
             LIBS="-lsocket -lnsl $LIBS",
               AC_CHECK_LIB(resolv, gethostbyname),
             -lnsl)
       )
     )
   )
  AC_CHECK_FUNC(socket, , AC_CHECK_LIB(socket, socket, ,
    AC_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", , -lnsl)))
  ])

AC_PREREQ(2.52)
AC_COPYRIGHT([Copyright 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003
Massachusetts Institute of Technology.
])
dnl
dnl Figure out the top of the source and build trees.  We depend on localdir
dnl being a relative pathname; we could make it general later, but for now 
dnl this is good enough.
dnl
AC_DEFUN(V5_SET_TOPDIR,[dnl
ifdef([AC_LOCALDIR], [dnl AC_LOCALDIR exists in 2.13, but not newer autoconfs.
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
],[
ac_reltopdir=
for x in . .. ../.. ../../.. ../../../..; do
	if test "x$ac_reltopdir" = "x" -a -r "$srcdir/$x/aclocal.m4" ; then
		ac_reltopdir=$x
	fi
done
if test "x$ac_reltopdir" = "x"; then
	echo "Configure could not determine the relative topdir"
	exit 1
fi
])
ac_topdir=$srcdir/$ac_reltopdir
ac_config_fragdir=$ac_reltopdir/config
krb5_pre_in=$ac_config_fragdir/pre.in
krb5_post_in=$ac_config_fragdir/post.in
echo "Looking for $srcdir/$ac_config_fragdir"
if test -d "$srcdir/$ac_config_fragdir"; then
  AC_CONFIG_AUX_DIR($ac_config_fragdir)
else
  AC_MSG_ERROR([can not find config/ directory in $ac_reltopdir])
fi
])dnl
dnl
dnl drop in standard rules for all configure files -- CONFIG_RULES
dnl
AC_DEFUN(CONFIG_RULES,[dnl
V5_SET_TOPDIR dnl
WITH_CC dnl
WITH_CCOPTS dnl
WITH_CPPOPTS dnl
WITH_LINKER dnl
WITH_LDOPTS dnl
WITH_KRB4 dnl
KRB5_AC_CHOOSE_ET dnl
KRB5_AC_CHOOSE_SS dnl
KRB5_AC_CHOOSE_DB dnl
dnl allow stuff in tree to access deprecated/private stuff for now
AC_DEFINE([KRB5_PRIVATE], 1, [Define only if building in-tree])
AC_DEFINE([KRB5_DEPRECATED], 1, [Define only if building in-tree])
AC_C_CONST dnl
WITH_NETLIB dnl
WITH_HESIOD dnl
AC_ARG_PROGRAM dnl
dnl
dnl This selects the correct autoconf file; either the one in our source tree,
dnl or the one found in the user's path.  $srcdir may be relative, and if so,
dnl it's relative to the directory of the configure script.  Since the 
dnl automatic makefile rules to rerun autoconf cd into that directory, the
dnl right thing happens.
dnl
dnl if test -f $srcdir/$ac_reltopdir/util/autoconf/autoconf ; then
dnl	AUTOCONF=$ac_reltopdir/util/autoconf/autoconf
dnl	AUTOCONFFLAGS='--macrodir=$(CONFIG_RELTOPDIR)/util/autoconf'
dnl	AUTOHEADER=$ac_reltopdir/util/autoconf/autoheader
dnl	AUTOHEADERFLAGS='--macrodir=$(CONFIG_RELTOPDIR)/util/autoconf'
dnl else
	AUTOCONF=autoconf
	AUTOCONFFLAGS=
	AUTOHEADER=autoheader
	AUTOHEADERFLAGS=
	AUTOCONFINCFLAGS="--include"
dnl fi
AC_SUBST(AUTOCONF)
AC_SUBST(AUTOCONFFLAGS)
AC_SUBST(AUTOCONFINCFLAGS)
AC_SUBST(AUTOHEADER)
AC_SUBST(AUTOHEADERFLAGS)
dnl
dnl This identifies the top of the source tree relative to the directory 
dnl in which the configure file lives.
dnl
CONFIG_RELTOPDIR=$ac_reltopdir
AC_SUBST(CONFIG_RELTOPDIR)
AC_SUBST(subdirs)
lib_frag=$srcdir/$ac_config_fragdir/lib.in
AC_SUBST_FILE(lib_frag)
libobj_frag=$srcdir/$ac_config_fragdir/libobj.in
AC_SUBST_FILE(libobj_frag)
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
  AC_DEFINE(SYS_ERRLIST_DECLARED,1,[Define if sys_errlist is defined in errno.h])
  AC_DEFINE(HAVE_SYS_ERRLIST,1,[Define if sys_errlist in libc])
else
  # This means that sys_errlist is not declared in errno.h, but may still
  # be in libc.
  AC_CACHE_CHECK([for sys_errlist in libc], krb5_cv_var_sys_errlist,
  [AC_TRY_LINK([extern int sys_nerr;], [if (1+sys_nerr < 0) return 1;],
  krb5_cv_var_sys_errlist=yes, krb5_cv_var_sys_errlist=no;)])
  if test $krb5_cv_var_sys_errlist = yes; then
    AC_DEFINE(HAVE_SYS_ERRLIST,1,[Define if sys_errlist in libc])
    # Do this cruft for backwards compatibility for now.
    AC_DEFINE(NEED_SYS_ERRLIST,1,[Define if need to declare sys_errlist])
  else
    AC_MSG_WARN([sys_errlist is neither in errno.h nor in libc])
  fi
fi])

dnl
dnl check for sigmask/sigprocmask -- CHECK_SIGPROCMASK
dnl
AC_DEFUN(CHECK_SIGPROCMASK,[
AC_MSG_CHECKING([for use of sigprocmask])
AC_CACHE_VAL(krb5_cv_func_sigprocmask_use,
[AC_TRY_LINK([#include <signal.h>], [sigprocmask(SIG_SETMASK,0,0);],
 krb5_cv_func_sigprocmask_use=yes,
AC_TRY_LINK([#include <signal.h>], [sigmask(1);], 
 krb5_cv_func_sigprocmask_use=no, krb5_cv_func_sigprocmask_use=yes))])
AC_MSG_RESULT($krb5_cv_func_sigprocmask_use)
if test $krb5_cv_func_sigprocmask_use = yes; then
 AC_DEFINE(USE_SIGPROCMASK)
fi
])dnl
dnl
AC_DEFUN(AC_PROG_ARCHIVE, [AC_CHECK_PROG(ARCHIVE, ar, ar cqv, false)])dnl
AC_DEFUN(AC_PROG_ARCHIVE_ADD, [AC_CHECK_PROG(ARADD, ar, ar cruv, false)])dnl
dnl
dnl check for <dirent.h> -- CHECK_DIRENT
dnl (may need to be more complex later)
dnl
AC_DEFUN(CHECK_DIRENT,[
AC_CHECK_HEADER(dirent.h,AC_DEFINE(USE_DIRENT_H,1,[Define if you have dirent.h functionality]))])dnl
dnl
dnl check if union wait is defined, or if WAIT_USES_INT -- CHECK_WAIT_TYPE
dnl
AC_DEFUN(CHECK_WAIT_TYPE,[
AC_MSG_CHECKING([if argument to wait is int *])
AC_CACHE_VAL(krb5_cv_struct_wait,
dnl Test for prototype clash - if there is none - then assume int * works
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/wait.h>
extern pid_t wait(int *);],[], krb5_cv_struct_wait=no,dnl
dnl Else fallback on old stuff
[AC_TRY_COMPILE(
[#include <sys/wait.h>], [union wait i;
#ifdef WEXITSTATUS
  WEXITSTATUS (i);
#endif
], 
	krb5_cv_struct_wait=yes, krb5_cv_struct_wait=no)])])
AC_MSG_RESULT($krb5_cv_struct_wait)
if test $krb5_cv_struct_wait = no; then
	AC_DEFINE(WAIT_USES_INT,1,[Define if wait takes int as a argument])
fi
])dnl
dnl
dnl check for POSIX signal handling -- CHECK_SIGNALS
dnl
AC_DEFUN(CHECK_SIGNALS,[
AC_CHECK_FUNC(sigprocmask,
AC_MSG_CHECKING(for sigset_t and POSIX_SIGNALS)
AC_CACHE_VAL(krb5_cv_type_sigset_t,
[AC_TRY_COMPILE(
[#include <signal.h>],
[sigset_t x],
krb5_cv_type_sigset_t=yes, krb5_cv_type_sigset_t=no)])
AC_MSG_RESULT($krb5_cv_type_sigset_t)
if test $krb5_cv_type_sigset_t = yes; then
  AC_DEFINE(POSIX_SIGNALS,1,[Define if POSIX signal handling is used])
fi
)])dnl
dnl
dnl check for signal type
dnl
dnl AC_RETSIGTYPE isn't quite right, but almost.
AC_DEFUN(KRB5_SIGTYPE,[
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
   stype=void
   AC_DEFINE(POSIX_SIGTYPE, 1, [Define if POSIX signal handlers are used])
else
  if test $ac_cv_type_signal = void; then
     stype=void
  else
     stype=int
  fi
fi
AC_DEFINE_UNQUOTED(krb5_sigtype, $stype, [Define krb5_sigtype to type of signal handler])dnl
])dnl
dnl
dnl check for POSIX setjmp/longjmp -- CHECK_SETJMP
dnl
AC_DEFUN(CHECK_SETJMP,[
AC_CHECK_FUNC(sigsetjmp,
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
dnl Check for IPv6 compile-time support.
dnl
AC_DEFUN(KRB5_AC_INET6,[
AC_CHECK_HEADERS(sys/types.h macsock.h sys/socket.h netinet/in.h netdb.h)
AC_CHECK_FUNCS(inet_ntop inet_pton getnameinfo)
dnl getaddrinfo test needs netdb.h, for proper compilation on alpha
dnl under OSF/1^H^H^H^H^HDigital^H^H^H^H^H^H^HTru64 UNIX, where it's
dnl a macro
AC_MSG_CHECKING(for getaddrinfo)
AC_CACHE_VAL(ac_cv_func_getaddrinfo,
[AC_TRY_LINK([#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif],[
struct addrinfo *ai;
getaddrinfo("kerberos.mit.edu", "echo", 0, &ai);
], ac_cv_func_getaddrinfo=yes, ac_cv_func_getaddrinfo=no)])
AC_MSG_RESULT($ac_cv_func_getaddrinfo)
if test $ac_cv_func_getaddrinfo = yes; then
  AC_DEFINE(HAVE_GETADDRINFO,1,[Define if you have the getaddrinfo function])
fi
dnl
AC_REQUIRE([KRB5_SOCKADDR_SA_LEN])dnl
AC_ARG_ENABLE([ipv6],
[  --enable-ipv6           enable IPv6 support
  --disable-ipv6          disable IPv6 support
                            (default: enable if available)], ,enableval=try)dnl
case "$enableval" in
  yes | try)
	KRB5_AC_CHECK_INET6
	if test "$enableval/$krb5_cv_inet6" = yes/no ; then
	  AC_MSG_ERROR(IPv6 support does not appear to be available)
	fi ;;
  no)	;;
  *)	AC_MSG_ERROR(bad value "$enableval" for enable-ipv6 option) ;;
esac
])dnl
dnl
AC_DEFUN(KRB5_AC_CHECK_TYPE_WITH_HEADERS,[
AC_MSG_CHECKING(for type $1)
changequote(<<,>>)dnl
varname=`echo $1 | sed 's,[ -],_,g'`
changequote([,])dnl
AC_CACHE_VAL(krb5_cv_$varname,[
AC_TRY_COMPILE([$2],[ $1 foo; ], eval krb5_cv_$varname=yes, eval krb5_cv_$varname=no)])
eval x="\$krb5_cv_$varname"
AC_MSG_RESULT($x)
if eval test "$x" = yes ; then
  AC_DEFINE_UNQUOTED(HAVE_`echo $varname | tr [[[a-z]]] [[[A-Z]]]`)
fi])
dnl
dnl
AC_DEFUN(KRB5_AC_CHECK_SOCKADDR_STORAGE,[
KRB5_AC_CHECK_TYPE_WITH_HEADERS(struct sockaddr_storage, [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_MACSOCK_H
#include <macsock.h>
#else
#include <sys/socket.h>
#endif
#include <netinet/in.h>
])])dnl
dnl
dnl
AC_DEFUN(KRB5_AC_CHECK_INET6,[
AC_REQUIRE([KRB5_AC_CHECK_SOCKADDR_STORAGE])dnl
AC_MSG_CHECKING(for IPv6 compile-time support)
AC_CACHE_VAL(krb5_cv_inet6,[
dnl NetBSD and Linux both seem to have gotten get*info but not getipnodeby*
dnl as of the time I'm writing this, so we'll use get*info only.
if test "$ac_cv_func_inet_ntop" != "yes" ; then
  krb5_cv_inet6=no
else
AC_TRY_COMPILE([
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_MACSOCK_H
#include <macsock.h>
#else
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#include <netdb.h>
],[
  struct sockaddr_in6 in;
  AF_INET6;
  IN6_IS_ADDR_LINKLOCAL (&in.sin6_addr);
],krb5_cv_inet6=yes,krb5_cv_inet6=no)])
fi
AC_MSG_RESULT($krb5_cv_inet6)
if test $krb5_cv_inet6 = yes ; then
  AC_DEFINE(KRB5_USE_INET6,1,[Define if we should compile in IPv6 support (even if we can't use it at run time)])
fi
])dnl
dnl
dnl Generic File existence tests
dnl 
dnl K5_AC_CHECK_FILE(FILE, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl
AC_DEFUN(K5_AC_CHECK_FILE,
[AC_REQUIRE([AC_PROG_CC])dnl
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
[AC_REQUIRE([AC_PROG_CC])dnl
for ac_file in $1
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
AC_DEFUN(WITH_KRB4,[
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
	KRB4_INCLUDES=
	KRB4_LIBPATH=
	KRB_ERR_H_DEP=
	krb5_cv_build_krb4_libs=no
	krb5_cv_krb4_libdir=
else
 AC_DEFINE([KRB5_KRB4_COMPAT], 1, [Define this if building with krb4 compat])
 if test $withval = yes; then
	AC_MSG_RESULT(built in krb4 support)
	KRB4_DEPLIB='$(TOPLIBD)/libkrb4$(DEPLIBEXT)'
	KRB4_LIB=-lkrb4
	KRB4_INCLUDES='-I$(SRCTOP)/include/kerberosIV -I$(BUILDTOP)/include/kerberosIV'
	KRB4_LIBPATH=
	KRB_ERR_H_DEP='$(BUILDTOP)/include/kerberosIV/krb_err.h'
	krb5_cv_build_krb4_libs=yes
	krb5_cv_krb4_libdir=
 else
	AC_MSG_RESULT(preinstalled krb4 in $withval)
	KRB4_LIB="-lkrb"
dnl	DEPKRB4_LIB="$withval/lib/libkrb.a"
	KRB4_INCLUDES="-I$withval/include"
	KRB4_LIBPATH="-L$withval/lib"
	KRB_ERR_H_DEP=
	krb5_cv_build_krb4_libs=no
	krb5_cv_krb4_libdir="$withval/lib"
 fi
fi
AC_SUBST(KRB4_INCLUDES)
AC_SUBST(KRB4_LIBPATH)
AC_SUBST(KRB4_LIB)
AC_SUBST(KRB4_DEPLIB)
AC_SUBST(KRB_ERR_H_DEP)
dnl We always compile the des425 library
DES425_DEPLIB='$(TOPLIBD)/libdes425$(DEPLIBEXT)'
DES425_LIB=-ldes425
AC_SUBST(DES425_DEPLIB)
AC_SUBST(DES425_LIB)
])dnl
dnl
dnl set $(CC) from --with-cc=value
dnl
AC_DEFUN(KRB5_INIT_CCOPTS,[CCOPTS=
])
dnl
AC_DEFUN(KRB5_AC_CHECK_FOR_CFLAGS,[
AC_BEFORE([$0],[AC_PROG_CC])
krb5_ac_cflags_set=${CFLAGS+set}
])
dnl
AC_DEFUN(WITH_CC_DEPRECATED_ARG,[dnl
AC_ARG_WITH([cc],AC_HELP_STRING(--with-cc=COMPILER,deprecated; use CC=...),
	    AC_MSG_ERROR(option --with-cc is deprecated; use CC=...))])
AC_DEFUN(WITH_CC,[dnl
AC_REQUIRE([KRB5_AC_CHECK_FOR_CFLAGS])dnl
AC_REQUIRE([WITH_CC_DEPRECATED_ARG])dnl
AC_REQUIRE([AC_PROG_CC])dnl
krb5_cv_prog_gcc=$ac_cv_c_compiler_gnu
if test $ac_cv_c_compiler_gnu = yes ; then
     HAVE_GCC=yes
     else HAVE_GCC=
fi
AC_SUBST(HAVE_GCC)
# maybe add -Waggregate-return, or can we assume that actually works by now?
# -Wno-comment is for SunOS system header <sys/stream.h>
extra_gcc_warn_opts="-Wall -Wmissing-prototypes -Wcast-qual \
 -Wcast-align -Wconversion -Wshadow -Wno-comment -pedantic"
if test "$GCC" = yes ; then
  if test "x$krb5_ac_cflags_set" = xset ; then
    AC_MSG_NOTICE(not adding extra gcc warning flags because CFLAGS was set)
  else
    AC_MSG_NOTICE(adding extra warning flags for gcc)
    CFLAGS="$CFLAGS $extra_gcc_warn_opts"
  fi
fi
])dnl
dnl
dnl set $(LD) from --with-linker=value
dnl
AC_DEFUN(WITH_LINKER,[
AC_ARG_WITH([linker],
	    AC_HELP_STRING(--with-linker=LINKER,deprecated; use LD=...),
	    AC_MSG_ERROR(option --with-linker is deprecated; use LD=...))
if test -z "$LD" ; then LD=$CC; fi
AC_ARG_VAR(LD,[linker command [CC]])
])dnl
dnl
dnl set $(CCOPTS) from --with-ccopts=value
dnl
AC_DEFUN(WITH_CCOPTS,[
AC_REQUIRE([KRB5_INIT_CCOPTS])dnl
AC_ARG_WITH([ccopts],
	    AC_HELP_STRING(--with-ccopts=CCOPTS, deprecated; use CFLAGS=...),
	    AC_MSG_ERROR(option --with-ccopts is deprecated; use CFLAGS=...))])
dnl
dnl set $(LDFLAGS) from --with-ldopts=value
dnl
AC_DEFUN(WITH_LDOPTS,[
AC_ARG_WITH([ldopts],
	    AC_HELP_STRING(--with-ldopts=LDOPTS,deprecated; use LDFLAGS=...),
	    AC_MSG_ERROR(option --with-ldopts is deprecated; use LDFLAGS=...))
AC_SUBST(LDFLAGS)])dnl
dnl
dnl set $(CPPOPTS) from --with-cppopts=value
dnl
AC_DEFUN(WITH_CPPOPTS,[
AC_REQUIRE_CPP
AC_ARG_WITH([cppopts],
	   AC_HELP_STRING(--with-cppopts=CPPOPTS,deprecated; use CPPFLAGS=...),
	   AC_MSG_ERROR(option --with-cppopts is deprecated; use CPPFLAGS=...))])
dnl
dnl check for yylineno -- HAVE_YYLINENO
dnl
AC_DEFUN(HAVE_YYLINENO,[dnl
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
	AC_DEFINE(NO_YYLINENO, 1, [Define if lex produes code with yylineno])
  fi
])dnl
dnl
dnl K5_GEN_MAKEFILE([dir, [frags]])
dnl
AC_DEFUN(K5_GEN_MAKEFILE,[dnl
ifelse($1, ,[_K5_GEN_MAKEFILE(.,$2)],[_K5_GEN_MAKEFILE($1,$2)])
])
dnl
dnl _K5_GEN_MAKEFILE(dir, [frags])
dnl  dir must be present in this case
dnl  Note: Be careful in quoting. 
dnl        The ac_foreach generates the list of fragments to include
dnl        or "" if $2 is empty
AC_DEFUN(_K5_GEN_MAKEFILE,[dnl
AC_CONFIG_FILES([$1/Makefile:$krb5_pre_in:$1/Makefile.in:$krb5_post_in])
])
dnl
dnl K5_GEN_FILE( <ac_output arguments> )
dnl
AC_DEFUN(K5_GEN_FILE,[AC_CONFIG_FILES($1)])dnl
dnl
dnl K5_AC_OUTPUT
dnl    Note: Adds the variables to config.status for individual 
dnl          Makefile generation from config.statsu
AC_DEFUN(K5_AC_OUTPUT,[dnl
AC_CONFIG_COMMANDS([krb5_config_prefix], [], dnl
 [krb5_pre_in=$krb5_pre_in
 ac_config_fragdir=$ac_config_fragdir
 krb5_post_in=$krb5_post_in])
AC_OUTPUT])dnl
dnl
dnl V5_AC_OUTPUT_MAKEFILE
dnl
AC_DEFUN(V5_AC_OUTPUT_MAKEFILE,
[ifelse($1, , [_V5_AC_OUTPUT_MAKEFILE(.,$2)],[_V5_AC_OUTPUT_MAKEFILE($1,$2)])])
dnl
define(_V5_AC_OUTPUT_MAKEFILE,
[ifelse($2, , ,AC_CONFIG_FILES($2))
AC_FOREACH([DIR], [$1],dnl
 [AC_CONFIG_FILES(DIR[/Makefile:$krb5_pre_in:]DIR[/Makefile.in:$krb5_post_in])])
K5_AC_OUTPUT])dnl
dnl
dnl
dnl KRB5_SOCKADDR_SA_LEN: define HAVE_SA_LEN if sockaddr contains the sa_len
dnl component
dnl
AC_DEFUN([KRB5_SOCKADDR_SA_LEN],[ dnl
AC_MSG_CHECKING(whether struct sockaddr contains sa_len)
AC_CACHE_VAL(krb5_cv_sockaddr_sa_len,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
],
[struct sockaddr sa;
sa.sa_len;],
krb5_cv_sockaddr_sa_len=yes,krb5_cv_sockaddr_sa_len=no)])
AC_MSG_RESULT([$]krb5_cv_sockaddr_sa_len)
if test $krb5_cv_sockaddr_sa_len = yes; then
   AC_DEFINE_UNQUOTED(HAVE_SA_LEN,1,[Define if struct sockaddr contains sa_len])
   fi
])
dnl
dnl
dnl CHECK_UTMP: check utmp structure and functions
dnl
AC_DEFUN(CHECK_UTMP,[
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
AC_CHECK_FUNC(setutent,AC_DEFINE(HAVE_SETUTENT))
AC_CHECK_FUNC(setutxent,AC_DEFINE(HAVE_SETUTXENT))
AC_CHECK_FUNC(updwtmp,AC_DEFINE(HAVE_UPDWTMP))
AC_CHECK_FUNC(updwtmpx,AC_DEFINE(HAVE_UPDWTMPX))
])dnl
dnl
dnl WITH_NETLIB
dnl 
dnl
AC_DEFUN(WITH_NETLIB,[
AC_ARG_WITH([netlib],
AC_HELP_STRING([--with-netlib=LIBS], use user defined resolver library),
[  if test "$withval" = yes -o "$withval" = no ; then
	AC_MSG_RESULT("netlib will link with C library resolver only")
  else
	LIBS="$LIBS $withval"
	AC_MSG_RESULT("netlib will use \'$withval\'")
  fi
],dnl
[AC_LIBRARY_NET]
)])dnl
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
  AC_DEFINE(HAVE_STDARG_H, 1, [Define if stdarg available and compiles])
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
  AC_DEFINE(HAVE_VARARGS_H, 1, [Define if varargs available and compiles])
else
  AC_MSG_ERROR(Neither stdarg nor varargs compile?)
fi

fi dnl stdarg test failure

])dnl

dnl
dnl KRB5_AC_NEED_LIBGEN --- check if libgen needs to be linked in for
dnl 				compile/step	
dnl
dnl
AC_DEFUN(KRB5_AC_NEED_LIBGEN,[
AC_REQUIRE([AC_PROG_CC])dnl
dnl
dnl regcomp is present but non-functional on Solaris 2.4
dnl
AC_MSG_CHECKING(for working regcomp)
AC_CACHE_VAL(ac_cv_func_regcomp,[
AC_TRY_RUN([
#include <sys/types.h>
#include <regex.h>
regex_t x; regmatch_t m;
int main() { return regcomp(&x,"pat.*",0) || regexec(&x,"pattern",1,&m,0); }
], ac_cv_func_regcomp=yes, ac_cv_func_regcomp=no, AC_MSG_ERROR([Cannot test regcomp when cross compiling]))])
AC_MSG_RESULT($ac_cv_func_regcomp)
test $ac_cv_func_regcomp = yes && AC_DEFINE(HAVE_REGCOMP,1,[Define if regcomp exists and functions])
dnl
dnl Check for the compile and step functions - only if regcomp is not available
dnl
if test $ac_cv_func_regcomp = no; then
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
fi
])
dnl
dnl KRB5_AC_REGEX_FUNCS --- check for different regular expression 
dnl				support functions
dnl
AC_DEFUN(KRB5_AC_REGEX_FUNCS,[
AC_CHECK_FUNCS(re_comp re_exec regexec)
AC_REQUIRE([KRB5_AC_NEED_LIBGEN])dnl
])dnl
dnl
dnl AC_KRB5_TCL_FIND_CONFIG (uses tcl_dir)
dnl
AC_DEFUN(AC_KRB5_TCL_FIND_CONFIG,[
AC_REQUIRE([KRB5_LIB_AUX])dnl
AC_MSG_CHECKING(for tclConfig.sh)
if test -r "$tcl_dir/lib/tclConfig.sh" ; then
  tcl_conf="$tcl_dir/lib/tclConfig.sh"
else
  tcl_conf=
  lib="$tcl_dir/lib"
  changequote(<<,>>)dnl
  for d in "$lib" "$lib"/tcl7.[0-9] "$lib"/tcl8.[0-9] ; do
    if test -r "$d/tclConfig.sh" ; then
      tcl_conf="$tcl_conf $d/tclConfig.sh"
    fi
  done
  changequote([,])dnl
fi
if test -n "$tcl_conf" ; then
  AC_MSG_RESULT($tcl_conf)
else
  AC_MSG_RESULT(not found)
fi
tcl_ok_conf=
tcl_vers_maj=
tcl_vers_min=
old_CPPFLAGS=$CPPFLAGS
old_LIBS=$LIBS
old_LDFLAGS=$LDFLAGS
if test -n "$tcl_conf" ; then
  for file in $tcl_conf ; do
    TCL_MAJOR_VERSION=x ; TCL_MINOR_VERSION=x
    AC_MSG_CHECKING(Tcl info in $file)
    . $file
    v=$TCL_MAJOR_VERSION.$TCL_MINOR_VERSION
    if test -z "$tcl_vers_maj" \
	|| test "$tcl_vers_maj" -lt "$TCL_MAJOR_VERSION" \
	|| test "$tcl_vers_maj" = "$TCL_MAJOR_VERSION" -a "$tcl_vers_min" -lt "$TCL_MINOR_VERSION" ; then
      for incdir in "$TCL_PREFIX/include/tcl$v" "$TCL_PREFIX/include" ; do
	if test -r "$incdir/tcl.h" -o -r "$incdir/tcl/tcl.h" ; then
	  CPPFLAGS="$old_CPPFLAGS -I$incdir"
	  break
	fi
      done
      LIBS="$old_LIBS `eval echo x $TCL_LIB_SPEC $TCL_LIBS | sed 's/^x//'`"
      LDFLAGS="$old_LDFLAGS $TCL_LD_FLAGS"
      AC_TRY_LINK( , [Tcl_CreateInterp ();],
	tcl_ok_conf=$file
	tcl_vers_maj=$TCL_MAJOR_VERSION
	tcl_vers_min=$TCL_MINOR_VERSION
	AC_MSG_RESULT($v - working),
	AC_MSG_RESULT($v - compilation failed)
      )
    else
      AC_MSG_RESULT(older version $v)
    fi
  done
fi
CPPFLAGS=$old_CPPFLAGS
LIBS=$old_LIBS
LDFLAGS=$old_LDFLAGS
tcl_header=no
tcl_lib=no
if test -n "$tcl_ok_conf" ; then
  . $tcl_ok_conf
  TCL_INCLUDES=
  for incdir in "$TCL_PREFIX/include/tcl$v" "$TCL_PREFIX/include" ; do
    if test -r "$incdir/tcl.h" -o -r "$incdir/tcl/tcl.h" ; then
      if test "$incdir" != "/usr/include" ; then
        TCL_INCLUDES=-I$incdir
      fi
      break
    fi
  done
  # Need eval because the first-level expansion could reference
  # variables like ${TCL_DBGX}.
  eval TCL_LIBS='"'$TCL_LIB_SPEC $TCL_LIBS $TCL_DL_LIBS'"'
  TCL_LIBPATH="-L$TCL_EXEC_PREFIX/lib"
  TCL_RPATH=":$TCL_EXEC_PREFIX/lib"
  if test "$DEPLIBEXT" != "$SHLIBEXT" && test -n "$RPATH_FLAG"; then
    TCL_MAYBE_RPATH='$(RPATH_FLAG)'"$TCL_EXEC_PREFIX/lib$RPATH_TAIL"
  else
    TCL_MAYBE_RPATH=
  fi
  CPPFLAGS="$old_CPPFLAGS $TCL_INCLUDES"
  AC_CHECK_HEADER(tcl.h,AC_DEFINE(HAVE_TCL_H) tcl_header=yes)
  if test $tcl_header=no; then
     AC_CHECK_HEADER(tcl/tcl.h,AC_DEFINE(HAVE_TCL_TCL_H) tcl_header=yes)
  fi
  CPPFLAGS="$old_CPPFLAGS"
  tcl_lib=yes
fi  
AC_SUBST(TCL_INCLUDES)
AC_SUBST(TCL_LIBS)
AC_SUBST(TCL_LIBPATH)
AC_SUBST(TCL_RPATH)
AC_SUBST(TCL_MAYBE_RPATH)
])dnl
dnl
dnl AC_KRB5_TCL_TRYOLD
dnl attempt to use old search algorithm for locating tcl
dnl
AC_DEFUN(AC_KRB5_TCL_TRYOLD, [
AC_MSG_WARN([trying old tcl search code])
if test "$with_tcl" != yes -a "$with_tcl" != no; then
	TCL_INCLUDES=-I$with_tcl/include
	TCL_LIBPATH=-L$with_tcl/lib
	TCL_RPATH=:$with_tcl/lib
fi
if test "$with_tcl" != no ; then
	AC_CHECK_LIB(dl, dlopen, DL_LIB=-ldl)
	AC_CHECK_LIB(ld, main, DL_LIB=-lld)
	krb5_save_CPPFLAGS="$CPPFLAGS"
	krb5_save_LDFLAGS="$LDFLAGS"
	CPPFLAGS="$CPPFLAGS $TCL_INCLUDES"
	LDFLAGS="$LDFLAGS $TCL_LIBPATH"
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
dnl AC_KRB5_TCL - determine if the TCL library is present on system
dnl
AC_DEFUN(AC_KRB5_TCL,[
TCL_INCLUDES=
TCL_LIBPATH=
TCL_RPATH=
TCL_LIBS=
TCL_WITH=
tcl_dir=
AC_ARG_WITH(tcl,
[  --with-tcl=path         where Tcl resides], , with_tcl=try)
if test "$with_tcl" = no ; then
  true
elif test "$with_tcl" = yes -o "$with_tcl" = try ; then
  tcl_dir=/usr
else
  tcl_dir=$with_tcl
fi
if test "$with_tcl" != no ; then
  AC_KRB5_TCL_FIND_CONFIG
  if test $tcl_lib = no ; then
    if test "$with_tcl" != try ; then
      AC_KRB5_TCL_TRYOLD
    else
      AC_MSG_WARN(Could not find Tcl which is needed for some tests)
    fi
  fi
fi
# If "yes" or pathname, error out if not found.
if test "$with_tcl" != no -a "$with_tcl" != try ; then
  if test "$tcl_header $tcl_lib" != "yes yes" ; then
    AC_MSG_ERROR(Could not find Tcl)
  fi
fi
])dnl

dnl
dnl WITH_HESIOD
dnl
AC_DEFUN(WITH_HESIOD,
[AC_ARG_WITH(hesiod, AC_HELP_STRING(--with-hesiod[=path], compile with hesiod support),
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
[KRB5_BUILD_LIBRARY_WITH_DEPS
# null out SHLIB_EXPFLAGS because we lack any dependencies
SHLIB_EXPFLAGS=])

dnl
dnl KRB5_BUILD_LIBRARY_STATIC
dnl
dnl Force static library build.

AC_DEFUN(KRB5_AC_FORCE_STATIC,[dnl
AC_BEFORE([$0],[KRB5_LIB_AUX])dnl
krb5_force_static=yes])
AC_DEFUN(KRB5_BUILD_LIBRARY_STATIC,
dnl Use define rather than AC_DEFUN to avoid ordering problems.
[AC_REQUIRE([KRB5_AC_FORCE_STATIC])dnl
KRB5_BUILD_LIBRARY
# If we're only building static libraries, they're for build-time use only,
# so don't install.
LIBINSTLIST=])

dnl
dnl KRB5_BUILD_LIBRARY_WITH_DEPS
dnl
dnl Like KRB5_BUILD_LIBRARY, but adds in explicit dependencies in the
dnl generated shared library.

AC_DEFUN(KRB5_BUILD_LIBRARY_WITH_DEPS,
[AC_REQUIRE([KRB5_LIB_AUX])dnl
AC_REQUIRE([AC_PROG_LN_S])dnl
AC_REQUIRE([AC_PROG_RANLIB])dnl
AC_REQUIRE([AC_PROG_ARCHIVE])dnl
AC_REQUIRE([AC_PROG_ARCHIVE_ADD])dnl
AC_REQUIRE([AC_PROG_INSTALL])dnl
AC_CHECK_PROG(AR, ar, ar, false)
AC_SUBST(LIBLIST)
AC_SUBST(LIBLINKS)
AC_SUBST(LDCOMBINE)
AC_SUBST(LDCOMBINE_TAIL)
AC_SUBST(SHLIB_EXPFLAGS)
AC_SUBST(INSTALL_SHLIB)
AC_SUBST(STLIBEXT)
AC_SUBST(SHLIBEXT)
AC_SUBST(SHLIBVEXT)
AC_SUBST(SHLIBSEXT)
AC_SUBST(DEPLIBEXT)
AC_SUBST(PFLIBEXT)
AC_SUBST(LIBINSTLIST)])

dnl
dnl KRB5_BUILD_LIBOBJS
dnl
dnl Pull in the necessary stuff to build library objects.

AC_DEFUN(KRB5_BUILD_LIBOBJS,
[AC_REQUIRE([KRB5_LIB_AUX])dnl
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
[AC_REQUIRE([KRB5_LIB_AUX])dnl
AC_REQUIRE([KRB5_AC_NEED_LIBGEN])dnl
AC_SUBST(CC_LINK)
AC_SUBST(RPATH_FLAG)
AC_SUBST(DEPLIBEXT)])

dnl
dnl KRB5_RUN_FLAGS
dnl
dnl Set up environment for running dynamic execuatbles out of build tree

AC_DEFUN(KRB5_RUN_FLAGS,
[AC_REQUIRE([KRB5_LIB_AUX])dnl
KRB5_RUN_ENV="$RUN_ENV"
AC_SUBST(KRB5_RUN_ENV)])

dnl
dnl KRB5_LIB_AUX
dnl
dnl Parse configure options related to library building.

AC_DEFUN(KRB5_LIB_AUX,
[AC_REQUIRE([KRB5_LIB_PARAMS])dnl
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
			SHLIBVEXT=.so.v-nobuild
			SHLIBSEXT=.so.s-nobuild
		else
			AC_MSG_RESULT([Enabling shared libraries.])
			# Clear some stuff in case of AIX, etc.
			if test "$STLIBEXT" = "$SHLIBEXT" ; then
				STLIBEXT=.a-nobuild
				LIBLIST=
				LIBLINKS=
				OBJLISTS=
				LIBINSTLIST=
			fi
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
	SHLIBEXT=.so-nobuild
	SHLIBVEXT=.so.v-nobuild
	SHLIBSEXT=.so.s-nobuild
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
[AC_REQUIRE([AC_CANONICAL_HOST])dnl
krb5_cv_host=$host
AC_SUBST(krb5_cv_host)
AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([V5_SET_TOPDIR])dnl
. $ac_topdir/config/shlib.conf])
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
   AC_CHECK_FUNC(gethostbyname, , [
     # Some OSes (eg. Solaris) place it in libnsl:
     AC_CHECK_LIB(nsl, gethostbyname, , [
       # Some strange OSes (SINIX) have it in libsocket:
       AC_CHECK_LIB(socket, gethostbyname, , [
          # Unfortunately libsocket sometimes depends on libnsl.
          # AC_CHECK_LIB's API is essentially broken so the following
          # ugliness is necessary:
          AC_CHECK_LIB(socket, gethostbyname,
             LIBS="-lsocket -lnsl $LIBS",
               [AC_CHECK_LIB(resolv, gethostbyname,
			     LIBS="-lresolv $LIBS" ; RESOLV_LIB=-lresolv)],
             -lnsl)
       ])
     ])
   ])
  AC_CHECK_FUNC(socket, , AC_CHECK_LIB(socket, socket, ,
    AC_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", , -lnsl)))
  KRB5_AC_ENABLE_DNS
  if test "$enable_dns" = yes ; then
    AC_CHECK_FUNC(res_search, , AC_CHECK_LIB(resolv, res_search,
	LIBS="$LIBS -lresolv" ; RESOLV_LIB=-lresolv,
	AC_MSG_ERROR(Cannot find resolver support routine res_search in -lresolv.)
    ))
  fi
  AC_SUBST(RESOLV_LIB)
  ])
dnl
dnl
dnl KRB5_AC_ENABLE_DNS
dnl
AC_DEFUN(KRB5_AC_ENABLE_DNS, [
AC_MSG_CHECKING(if DNS Kerberos lookup support should be compiled in)

  AC_ARG_ENABLE([dns],
[  --enable-dns            build in support for Kerberos-related DNS lookups], ,
[enable_dns=default])

  AC_ARG_ENABLE([dns-for-kdc],
[  --enable-dns-for-kdc    enable DNS lookups of Kerberos KDCs (default=YES)], ,
[case "$enable_dns" in
  yes | no) enable_dns_for_kdc=$enable_dns ;;
  *) enable_dns_for_kdc=yes ;;
esac])
  if test "$enable_dns_for_kdc" = yes; then
    AC_DEFINE(KRB5_DNS_LOOKUP_KDC,1,[Define to enable DNS lookups of Kerberos KDCs])
  fi

  AC_ARG_ENABLE([dns-for-realm],
[  --enable-dns-for-realm  enable DNS lookups of Kerberos realm names], ,
[case "$enable_dns" in
  yes | no) enable_dns_for_realm=$enable_dns ;;
  *) enable_dns_for_realm=no ;;
esac])
  if test "$enable_dns_for_realm" = yes; then
    AC_DEFINE(KRB5_DNS_LOOKUP_REALM,1,[Define to enable DNS lookups of Kerberos realm names])
  fi

  if test "$enable_dns_for_kdc,$enable_dns_for_realm" != no,no
  then
    # must compile in the support code
    if test "$enable_dns" = no ; then
      AC_MSG_ERROR(cannot both enable some DNS options and disable DNS support)
    fi
    enable_dns=yes
  fi
  if test "$enable_dns" = yes ; then
    AC_DEFINE(KRB5_DNS_LOOKUP, 1,[Define for DNS support of locating realms and KDCs])
  else
    enable_dns=no
  fi

AC_MSG_RESULT($enable_dns)
dnl AC_MSG_CHECKING(if DNS should be used to find KDCs by default)
dnl AC_MSG_RESULT($enable_dns_for_kdc)
dnl AC_MSG_CHECKING(if DNS should be used to find realm name by default)
dnl AC_MSG_RESULT($enable_dns_for_realm)
])
dnl
dnl
dnl Check if we need the prototype for a function - we give it a bogus 
dnl prototype and if it complains - then a valid prototype exists on the 
dnl system.
dnl
dnl KRB5_NEED_PROTO(includes, function, [bypass])
dnl if $3 set, don't see if library defined. 
dnl Useful for case where we will define in libkrb5 the function if need be
dnl but want to know if a prototype exists in either case on system.
dnl
AC_DEFUN([KRB5_NEED_PROTO], [
ifelse([$3], ,[if test "x$ac_cv_func_$2" = xyes; then])
AC_CACHE_CHECK([if $2 needs a prototype provided], krb5_cv_func_$2_noproto,
AC_TRY_COMPILE([$1],
[struct k5foo {int foo; } xx;
extern int $2 (struct k5foo*);
$2(&xx);
],
krb5_cv_func_$2_noproto=yes,krb5_cv_func_$2_noproto=no))
if test $krb5_cv_func_$2_noproto = yes; then
	AC_DEFINE([NEED_]translit($2, [a-z], [A-Z])[_PROTO], 1, dnl
[define if the system header files are missing prototype for $2()])
fi
ifelse([$3], ,[fi])
])
dnl
dnl =============================================================
dnl Internal function for testing for getpeername prototype
dnl
AC_DEFUN([TRY_PEER_INT],[
krb5_lib_var=`echo "$1 $2" | sed 'y% ./+-*%___p_p%'`
AC_MSG_CHECKING([if getpeername() takes arguments $1 and $2])
AC_CACHE_VAL(krb5_cv_getpeername_proto$krb5_lib_var,
[
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
extern int getpeername(int, $1, $2);
],,eval "krb5_cv_getpeername_proto$krb5_lib_var=yes", 
   eval "krb5_cv_getpeername_proto$krb5_lib_var=no")])
if eval "test \"`echo '$krb5_cv_getpeername_proto'$krb5_lib_var`\" = yes"; then
	AC_MSG_RESULT(yes)
	peer_set=yes
	res1=`echo "$1" | tr -d '*' | sed -e 's/ *$//'`
	res2=`echo "$2" | tr -d '*' | sed -e 's/ *$//'`
	AC_DEFINE_UNQUOTED([GETPEERNAME_ARG2_TYPE],$res1)
	AC_DEFINE_UNQUOTED([GETPEERNAME_ARG3_TYPE],$res2)
else
	AC_MSG_RESULT(no)
fi
])
dnl
dnl Determines the types of the second and third arguments to getpeername()
dnl Note: It is possible that noe of the combinations will work and the
dnl code must deal
AC_DEFUN([KRB5_GETPEERNAME_ARGS],[
peer_set=no
for peer_arg1 in "struct sockaddr *" "void *"
do
  for peer_arg2 in "size_t *" "int *" "socklen_t *"
  do
	if test $peer_set = no; then
	  TRY_PEER_INT($peer_arg1, $peer_arg2)
	fi
  done 
done
])
dnl
dnl =============================================================
dnl Internal function for testing for getsockname arguments
dnl
AC_DEFUN([TRY_GETSOCK_INT],[
krb5_lib_var=`echo "$1 $2" | sed 'y% ./+-*%___p_p%'`
AC_MSG_CHECKING([if getsockname() takes arguments $1 and $2])
AC_CACHE_VAL(krb5_cv_getsockname_proto_$krb5_lib_var,
[
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
extern int getsockname(int, $1, $2);
],,eval "krb5_cv_getsockname_proto_$krb5_lib_var=yes",
    eval "krb5_cv_getsockname_proto_$krb5_lib_var=no")])
if eval "test \"`echo '$krb5_cv_getsockname_proto_'$krb5_lib_var`\" = yes"; then
	AC_MSG_RESULT(yes)
	sock_set=yes
	res1=`echo "$1" | tr -d '*' | sed -e 's/ *$//'`
	res2=`echo "$2" | tr -d '*' | sed -e 's/ *$//'`
	AC_DEFINE_UNQUOTED([GETSOCKNAME_ARG2_TYPE],$res1)
	AC_DEFINE_UNQUOTED([GETSOCKNAME_ARG3_TYPE],$res2)
else
	AC_MSG_RESULT(no)
fi
])
dnl
dnl Determines the types of the second and third arguments to getsockname()
dnl Note: It is possible that noe of the combinations will work and the
dnl code must deal
AC_DEFUN([KRB5_GETSOCKNAME_ARGS],[
sock_set=no
for sock_arg1 in "struct sockaddr *" "void *"
do
  for sock_arg2 in "size_t *" "int *" "socklen_t *"
  do
	if test $sock_set = no; then
	  TRY_GETSOCK_INT($sock_arg1, $sock_arg2)
	fi
  done 
done
])
dnl
dnl
AC_DEFUN([KRB5_AC_CHOOSE_ET],[
AC_ARG_WITH([system-et],
AC_HELP_STRING(--with-system-et,use system compile_et and -lcom_err @<:@default: build and install a local version@:>@))
AC_MSG_CHECKING(which version of com_err to use)
if test "x$with_system_et" = xyes ; then
  COM_ERR_VERSION=sys
  AC_MSG_RESULT(system)
else
  COM_ERR_VERSION=k5
  AC_MSG_RESULT(krb5)
fi
if test $COM_ERR_VERSION = sys; then
  # check for various functions we need
  AC_CHECK_LIB(com_err, add_error_table, :, AC_MSG_ERROR(cannot find add_error_table in com_err library))
  AC_CHECK_LIB(com_err, remove_error_table, :, AC_MSG_ERROR(cannot find remove_error_table in com_err library))
  # make sure compile_et provides "et_foo" name
  cat >> conf$$e.et <<EOF
error_table foo
error_code ERR_FOO, "foo"
end
EOF
  AC_CHECK_PROGS(compile_et,compile_et,false)
  if test "$compile_et" = false; then
    AC_MSG_ERROR(cannot find compile_et)
  fi
  AC_CACHE_CHECK(whether compile_et is useful,krb5_cv_compile_et_useful,[
  if compile_et conf$$e.et >/dev/null 2>&1 ; then true ; else
    AC_MSG_ERROR(execution failed)
  fi
  AC_TRY_COMPILE([#include "conf$$e.h"
      		 ],[ et_foo_error_table; ],:,
		 [AC_MSG_ERROR(cannot use et_foo_error_table)])
  # Anything else we need to test for?
  rm -f conf$$e.et conf$$e.c conf$$e.h
  krb5_cv_compile_et_useful=yes
  ])
fi
AC_SUBST(COM_ERR_VERSION)
])
AC_DEFUN([KRB5_AC_CHOOSE_SS],[
AC_ARG_WITH(system-ss,
	    AC_HELP_STRING(--with-system-ss,use system -lss and mk_cmds @<:@default: use a private version@:>@))
AC_ARG_VAR(SS_LIB,[system libraries for 'ss' package, if --with-system-ss was specified [-lss]])
AC_MSG_CHECKING(which version of subsystem package to use)
if test "x$with_system_ss" = xyes ; then
  SS_VERSION=sys
  AC_MSG_RESULT(system)
  # todo: check for various libraries we might need
  # in the meantime...
  test "x${SS_LIB+set}" = xset || SS_LIB=-lss
  old_LIBS="$LIBS"
  LIBS="$LIBS $SS_LIB"
  AC_CACHE_CHECK(whether system ss package works, krb5_cv_system_ss_okay,[
  AC_TRY_RUN([
#include <ss/ss.h>
int main(int argc, char *argv[]) {
  if (argc == 42) {
    int i, err;
    i = ss_create_invocation("foo","foo","",0,&err);
    ss_listen(i);
  }
  return 0;
}], krb5_cv_system_ss_okay=yes, AC_MSG_ERROR(cannot run test program),
  krb5_cv_system_ss_okay="assumed")])
  LIBS="$old_LIBS"
else
  SS_VERSION=k5
  AC_MSG_RESULT(krb5)
fi
AC_SUBST(SS_LIB)
AC_SUBST(SS_VERSION)
])
dnl
AC_DEFUN([KRB5_AC_CHOOSE_DB],[
AC_ARG_WITH(system-db,
	    AC_HELP_STRING(--with-system-db,use system Berkeley db library @<:@default: use a private version@:>@))
AC_ARG_VAR(DB_HEADER,[header file to include for Berkeley db package, if --with-system-db was specified [db.h]])
AC_ARG_VAR(DB_LIB,[system library for Berkeley db package, if --with-system-db was specified [-ldb]])
if test "x$with_system_db" = xyes ; then
  DB_VERSION=sys
  # TODO: Do we have specific routines we should check for?
  # How about known, easily recognizable bugs?
  # We want to use bt_rseq in some cases, but no other version but
  # ours has it right now.
  #
  # Okay, check the variables.
  test "x${DB_HEADER+set}" = xset || DB_HEADER=db.h
  test "x${DB_LIB+set}" = xset || DB_LIB=-ldb
  #
  if test "x${DB_HEADER}" = xdb.h ; then
    DB_HEADER_VERSION=sys
  else
    DB_HEADER_VERSION=redirect
  fi
  KDB5_DB_LIB="$DB_LIB"
else
  DB_VERSION=k5
  AC_DEFINE(HAVE_BT_RSEQ,1,[Define if bt_rseq is available, for recursive btree traversal.])
  DB_HEADER=db.h
  DB_HEADER_VERSION=k5
  # libdb gets sucked into libkdb
  KDB5_DB_LIB=
  # needed for a couple of things that need libdb for its own sake
  DB_LIB=-ldb
fi
AC_SUBST(DB_VERSION)
AC_SUBST(DB_HEADER)
AC_SUBST(DB_HEADER_VERSION)
AC_SUBST(DB_LIB)
AC_SUBST(KDB5_DB_LIB)
])
dnl
dnl
dnl KRB5_AC_NEED_BIND_8_COMPAT --- check to see if we are on a bind 9 system
dnl
dnl
AC_DEFUN(KRB5_AC_NEED_BIND_8_COMPAT,[
AC_REQUIRE([AC_PROG_CC])dnl
dnl
dnl On a bind 9 system, we need to define BIND_8_COMPAT
dnl
AC_MSG_CHECKING(for bind 9 or higher)
AC_CACHE_VAL(krb5_cv_need_bind_8_compat,[
AC_TRY_COMPILE([#include <arpa/nameser.h>], [HEADER hdr;],
krb5_cv_need_bind_8_compat=no, 
[AC_TRY_COMPILE([#define BIND_8_COMPAT
#include <arpa/nameser.h>], [HEADER hdr;],
krb5_cv_need_bind_8_compat=yes, krb5_cv_need_bind_8_compat=no)])])
AC_MSG_RESULT($krb5_cv_need_bind_8_compat)
test $krb5_cv_need_bind_8_compat = yes && AC_DEFINE(BIND_8_COMPAT,1,[Define if OS has bind 9])
])
dnl

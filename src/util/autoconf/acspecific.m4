dnl Macros that test for specific features.
dnl This file is part of Autoconf.
dnl Copyright (C) 1992, 1993, 1994 Free Software Foundation, Inc.
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2, or (at your option)
dnl any later version.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
dnl GNU General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
dnl
dnl As a special exception, the Free Software Foundation gives unlimited
dnl permission to copy, distribute and modify the configure scripts that
dnl are the output of Autoconf.  You need not follow the terms of the GNU
dnl General Public License when using or distributing such scripts, even
dnl though portions of the text of Autoconf appear in them.  The GNU
dnl General Public License (GPL) does govern all other use of the material
dnl that constitutes the Autoconf program.
dnl
dnl Certain portions of the Autoconf source text are designed to be copied
dnl (in certain cases, depending on the input) into the output of
dnl Autoconf.  We call these the "data" portions.  The rest of the Autoconf
dnl source text consists of comments plus executable code that decides which
dnl of the data portions to output in any given case.  We call these
dnl comments and executable code the "non-data" portions.  Autoconf never
dnl copies any of the non-data portions into its output.
dnl
dnl This special exception to the GPL applies to versions of Autoconf
dnl released by the Free Software Foundation.  When you make and
dnl distribute a modified version of Autoconf, you may extend this special
dnl exception to the GPL to apply to your modified version as well, *unless*
dnl your modified version has the potential to copy into its output some
dnl of the text that was the non-data portion of the version that you started
dnl with.  (In other words, unless your change moves or copies text from
dnl the non-data portions to the data portions.)  If your modification has
dnl such potential, you must delete any notice of this special exception
dnl to the GPL from your modified version.
dnl
dnl Written by David MacKenzie, with help from
dnl Franc,ois Pinard, Karl Berry, Richard Pixley, Ian Lance Taylor,
dnl Roland McGrath, Noah Friedman, david d zuhn, and many others.


dnl ### Checks for programs


dnl Check whether to use -n, \c, or newline-tab to separate
dnl checking messages from result messages.
dnl Idea borrowed from dist 3.0.
dnl Internal use only.
AC_DEFUN(AC_PROG_ECHO_N,
[if (echo "testing\c"; echo 1,2,3) | grep c >/dev/null; then
  # Stardent Vistra SVR4 grep lacks -e, says ghazi@caip.rutgers.edu.
  if (echo -n testing; echo 1,2,3) | sed s/-n/xn/ | grep xn >/dev/null; then
    ac_n= ac_c='
' ac_t='	'
  else
    ac_n=-n ac_c= ac_t=
  fi
else
  ac_n= ac_c='\c' ac_t=
fi
])

AC_DEFUN(AC_PROG_CC,
[AC_BEFORE([$0], [AC_PROG_CPP])dnl
AC_CHECK_PROG(CC, gcc, gcc, cc)

AC_MSG_CHECKING(whether we are using GNU C)
AC_CACHE_VAL(ac_cv_prog_gcc,
[dnl The semicolon is to pacify NeXT's syntax-checking cpp.
cat > conftest.c <<EOF
#ifdef __GNUC__
  yes;
#endif
EOF
if ${CC-cc} -E conftest.c 2>&AC_FD_CC | egrep yes >/dev/null 2>&1; then
  ac_cv_prog_gcc=yes
else
  ac_cv_prog_gcc=no
fi])dnl
AC_MSG_RESULT($ac_cv_prog_gcc)
if test $ac_cv_prog_gcc = yes; then
  GCC=yes
  if test "${CFLAGS+set}" != set; then
    AC_MSG_CHECKING(whether ${CC-cc} accepts -g)
AC_CACHE_VAL(ac_cv_prog_gcc_g,
[echo 'void f(){}' > conftest.c
if test -z "`${CC-cc} -g -c conftest.c 2>&1`"; then
  ac_cv_prog_gcc_g=yes
else
  ac_cv_prog_gcc_g=no
fi
rm -f conftest*
])dnl
    AC_MSG_RESULT($ac_cv_prog_gcc_g)
    if test $ac_cv_prog_gcc_g = yes; then
      CFLAGS="-g -O"
    else
      CFLAGS="-O"
    fi
  fi
else
  GCC=
  test "${CFLAGS+set}" = set || CFLAGS="-g"
fi
])

AC_DEFUN(AC_PROG_CXX,
[AC_BEFORE([$0], [AC_PROG_CXXCPP])dnl
AC_CHECK_PROGS(CXX, $CCC c++ g++ gcc CC cxx, gcc)

AC_MSG_CHECKING(whether we are using GNU C++)
AC_CACHE_VAL(ac_cv_prog_gxx,
[dnl The semicolon is to pacify NeXT's syntax-checking cpp.
cat > conftest.C <<EOF
#ifdef __GNUC__
  yes;
#endif
EOF
if ${CXX-g++} -E conftest.C 2>&AC_FD_CC | egrep yes >/dev/null 2>&1; then
  ac_cv_prog_gxx=yes
else
  ac_cv_prog_gxx=no
fi])dnl
AC_MSG_RESULT($ac_cv_prog_gxx)
if test $ac_cv_prog_gxx = yes; then
  GXX=yes
  if test "${CXXFLAGS+set}" != set; then
    AC_MSG_CHECKING(whether ${CXX-g++} accepts -g)
AC_CACHE_VAL(ac_cv_prog_gxx_g,
[echo 'void f(){}' > conftest.cc
if test -z "`${CXX-g++} -g -c conftest.cc 2>&1`"; then
  ac_cv_prog_gxx_g=yes
else
  ac_cv_prog_gxx_g=no
fi
rm -f conftest*
])dnl
    AC_MSG_RESULT($ac_cv_prog_gxx_g)
    if test $ac_cv_prog_gxx_g = yes; then
      CXXFLAGS="-g -O"
    else
      CXXFLAGS="-O"
    fi
  fi
else
  GXX=
  test "${CXXFLAGS+set}" = set || CXXFLAGS="-g"
fi
])

AC_DEFUN(AC_PROG_GCC_TRADITIONAL,
[AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([AC_PROG_CPP])dnl
if test $ac_cv_prog_gcc = yes; then
  AC_MSG_CHECKING(whether ${CC-cc} needs -traditional)
AC_CACHE_VAL(ac_cv_prog_gcc_traditional,
[  ac_pattern="Autoconf.*'x'"
  AC_EGREP_CPP($ac_pattern, [#include <sgtty.h>
Autoconf TIOCGETP],
  ac_cv_prog_gcc_traditional=yes, ac_cv_prog_gcc_traditional=no)

  if test $ac_cv_prog_gcc_traditional = no; then
    AC_EGREP_CPP($ac_pattern, [#include <termio.h>
Autoconf TCGETA],
    ac_cv_prog_gcc_traditional=yes)
  fi])dnl
  AC_MSG_RESULT($ac_cv_prog_gcc_traditional)
  if test $ac_cv_prog_gcc_traditional = yes; then
    CC="$CC -traditional"
  fi
fi
])

AC_DEFUN(AC_PROG_CC_C_O,
[if test "x$CC" != xcc; then
  AC_MSG_CHECKING(whether $CC and cc understand -c and -o together)
else
  AC_MSG_CHECKING(whether cc understands -c and -o together)
fi
set dummy $CC; ac_cc=[$]2
AC_CACHE_VAL(ac_cv_prog_cc_${ac_cc}_c_o,
[eval ac_cv_prog_cc_${ac_cc}_c_o=no
echo 'foo(){}' > conftest.c
# Make sure it works both with $CC and with simple cc.
# We do the test twice because some compilers refuse to overwrite an
# existing .o file with -o, though they will create one.
if ${CC-cc} -c conftest.c -o conftest.o 1>&AC_FD_CC 2>&AC_FD_CC &&
  test -f conftest.o && ${CC-cc} -c conftest.c -o conftest.o 1>&AC_FD_CC 2>&AC_FD_CC
then
  if test "x$CC" != xcc; then
    # Test first that cc exists at all.
    if cc -c conftest.c 1>&AC_FD_CC 2>&AC_FD_CC
    then
      if cc -c conftest.c -o conftest2.o 1>&AC_FD_CC 2>&AC_FD_CC &&
        test -f conftest2.o && cc -c conftest.c -o conftest2.o 1>&AC_FD_CC 2>&AC_FD_CC
      then
        eval ac_cv_prog_cc_${ac_cc}_c_o=yes
      fi
    fi
  fi
fi
rm -f conftest*
])dnl
if eval "test \"`echo '$ac_cv_prog_cc_'${ac_cc}_c_o`\" = yes"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
  AC_DEFINE(NO_MINUS_C_MINUS_O)
fi
])

dnl Define SET_MAKE to set ${MAKE} if make doesn't.
AC_DEFUN(AC_PROG_MAKE_SET,
[AC_MSG_CHECKING(whether ${MAKE-make} sets \$MAKE)
set dummy ${MAKE-make}; ac_make=[$]2
AC_CACHE_VAL(ac_cv_prog_make_${ac_make}_set,
[cat > conftestmake <<\EOF
all:
	@echo 'ac_maketemp="${MAKE}"'
EOF
changequote(, )dnl
# GNU make sometimes prints "make[1]: Entering...", which would confuse us.
eval `${MAKE-make} -f conftestmake 2>/dev/null | grep temp=`
changequote([, ])dnl
if test -n "$ac_maketemp"; then
  eval ac_cv_prog_make_${ac_make}_set=yes
else
  eval ac_cv_prog_make_${ac_make}_set=no
fi
rm -f conftestmake])dnl
if eval "test \"`echo '$ac_cv_prog_make_'${ac_make}_set`\" = yes"; then
  AC_MSG_RESULT(yes)
  SET_MAKE=
else
  AC_MSG_RESULT(no)
  SET_MAKE="MAKE=${MAKE-make}"
fi
AC_SUBST([SET_MAKE])dnl
])

AC_DEFUN(AC_PROG_RANLIB,
[AC_CHECK_PROG(RANLIB, ranlib, ranlib, :)])

dnl Check for mawk first since it's said to be faster.
AC_DEFUN(AC_PROG_AWK,
[AC_CHECK_PROGS(AWK, mawk gawk nawk awk, )])

AC_DEFUN(AC_PROG_YACC,
[AC_CHECK_PROGS(YACC, 'bison -y' byacc, yacc)])

AC_DEFUN(AC_PROG_CPP,
[AC_MSG_CHECKING(how to run the C preprocessor)
# On Suns, sometimes $CPP names a directory.
if test -n "$CPP" && test -d "$CPP"; then
  CPP=
fi
if test -z "$CPP"; then
AC_CACHE_VAL(ac_cv_prog_CPP,
[  # This must be in double quotes, not single quotes, because CPP may get
  # substituted into the Makefile and "${CC-cc}" will confuse make.
  CPP="${CC-cc} -E"
  # On the NeXT, cc -E runs the code through the compiler's parser,
  # not just through cpp.
dnl Use a header file that comes with gcc, so configuring glibc
dnl with a fresh cross-compiler works.
  AC_TRY_CPP([#include <assert.h>
Syntax Error], ,
  CPP="${CC-cc} -E -traditional-cpp"
  AC_TRY_CPP([#include <assert.h>
Syntax Error], , CPP=/lib/cpp))
  ac_cv_prog_CPP="$CPP"])dnl
fi
CPP="$ac_cv_prog_CPP"
AC_MSG_RESULT($CPP)
AC_SUBST(CPP)dnl
])

AC_DEFUN(AC_PROG_CXXCPP,
[AC_MSG_CHECKING(how to run the C++ preprocessor)
if test -z "$CXXCPP"; then
AC_CACHE_VAL(ac_cv_prog_CXXCPP,
[AC_LANG_SAVE[]dnl
AC_LANG_CPLUSPLUS[]dnl
  CXXCPP="${CXX-g++} -E"
  AC_TRY_CPP([#include <stdlib.h>], , CXXCPP=/lib/cpp)
  ac_cv_prog_CXXCPP="$CXXCPP"
AC_LANG_RESTORE[]dnl
fi])dnl
CXXCPP="$ac_cv_prog_CXXCPP"
AC_MSG_RESULT($CXXCPP)
AC_SUBST(CXXCPP)dnl
])

dnl Require finding the C or C++ preprocessor, whichever is the
dnl current language.
AC_DEFUN(AC_REQUIRE_CPP,
[ifelse(AC_LANG, C, [AC_REQUIRE([AC_PROG_CPP])], [AC_REQUIRE([AC_PROG_CXXCPP])])])

AC_DEFUN(AC_PROG_LEX,
[AC_CHECK_PROG(LEX, flex, flex, lex)
if test -z "$LEXLIB"
then
  case "$LEX" in
  flex*) ac_lib=fl ;;
  *) ac_lib=l ;;
  esac
  AC_CHECK_LIB($ac_lib, main, LEXLIB="-l$ac_lib")
fi
AC_SUBST(LEXLIB)])

AC_DEFUN(AC_DECL_YYTEXT,
[AC_REQUIRE_CPP()dnl
AC_REQUIRE([AC_PROG_LEX])dnl
AC_MSG_CHECKING(for yytext declaration)
AC_CACHE_VAL(ac_cv_prog_lex_yytext_pointer,
[# POSIX says lex can declare yytext either as a pointer or an array; the
# default is implementation-dependent. Figure out which it is, since
# not all implementations provide the %pointer and %array declarations.
#
# The minimal lex program is just a single line: %%.  But some broken lexes
# (Solaris, I think it was) want two %% lines, so accommodate them.
ac_cv_prog_lex_yytext_pointer=no
  echo '%%
%%' | $LEX
if test -f lex.yy.c; then
  LEX_OUTPUT_ROOT=lex.yy
elif test -f lexyy.c; then
  LEX_OUTPUT_ROOT=lexyy
else
  AC_MSG_ERROR(cannot find output from $LEX, giving up)
fi
echo 'extern char *yytext; main () { exit (0); }' >>$LEX_OUTPUT_ROOT.c
ac_save_LIBS="$LIBS"
LIBS="$LIBS $LEXLIB"
AC_TRY_LINK(`cat $LEX_OUTPUT_ROOT.c`, ac_cv_prog_lex_yytext_pointer=yes)
LIBS="$ac_save_LIBS"
rm -f "${LEX_OUTPUT_ROOT}.c"])dnl
AC_MSG_RESULT($ac_cv_prog_lex_yytext_pointer)
if test $ac_cv_prog_lex_yytext_pointer = yes; then
  AC_DEFINE(YYTEXT_POINTER)
fi
AC_SUBST(LEX_OUTPUT_ROOT)dnl
])

AC_DEFUN(AC_PROG_INSTALL,
[AC_REQUIRE([AC_CONFIG_AUX_DIR_DEFAULT])dnl
# Find a good install program.  We prefer a C program (faster),
# so one script is as good as another.  But avoid the broken or
# incompatible versions:
# SysV /etc/install, /usr/sbin/install
# SunOS /usr/etc/install
# IRIX /sbin/install
# AIX /bin/install
# AFS /usr/afsws/bin/install, which mishandles nonexistent args
# SVR4 /usr/ucb/install, which tries to use the nonexistent group "staff"
# ./install, which can be erroneously created by make from ./install.sh.
AC_MSG_CHECKING(for a BSD compatible install)
if test -z "$INSTALL"; then
AC_CACHE_VAL(ac_cv_path_install,
[  IFS="${IFS= 	}"; ac_save_ifs="$IFS"; IFS="${IFS}:"
  for ac_dir in $PATH; do
    case "$ac_dir" in
    ''|.|/etc|/usr/sbin|/usr/etc|/sbin|/usr/afsws/bin|/usr/ucb) ;;
    *)
      # OSF1 and SCO ODT 3.0 have their own names for install.
      for ac_prog in ginstall installbsd scoinst install; do
        if test -f $ac_dir/$ac_prog; then
	  if test $ac_prog = install &&
            grep dspmsg $ac_dir/$ac_prog >/dev/null 2>&1; then
	    # AIX install.  It has an incompatible calling convention.
	    # OSF/1 installbsd also uses dspmsg, but is usable.
	    :
	  else
	    ac_cv_path_install="$ac_dir/$ac_prog -c"
	    break 2
	  fi
	fi
      done
      ;;
    esac
  done
  IFS="$ac_save_ifs"
  # As a last resort, use the slow shell script.
  test -z "$ac_cv_path_install" && ac_cv_path_install="$ac_install_sh"])dnl
  INSTALL="$ac_cv_path_install"
fi
dnl We do special magic for INSTALL instead of AC_SUBST, to get
dnl relative paths right. 
AC_MSG_RESULT($INSTALL)

# Use test -z because SunOS4 sh mishandles braces in ${var-val}.
# It thinks the first close brace ends the variable substitution.
test -z "$INSTALL_PROGRAM" && INSTALL_PROGRAM='${INSTALL}'
AC_SUBST(INSTALL_PROGRAM)dnl

test -z "$INSTALL_DATA" && INSTALL_DATA='${INSTALL} -m 644'
AC_SUBST(INSTALL_DATA)dnl
])

AC_DEFUN(AC_PROG_LN_S,
[AC_MSG_CHECKING(whether ln -s works)
AC_CACHE_VAL(ac_cv_prog_LN_S,
[rm -f conftestdata
if ln -s X conftestdata 2>/dev/null
then
  rm -f conftestdata
  ac_cv_prog_LN_S="ln -s"
else
  ac_cv_prog_LN_S=ln
fi])dnl
LN_S="$ac_cv_prog_LN_S"
if test "$ac_cv_prog_LN_S" = "ln -s"; then
  AC_MSG_RESULT(yes)
else
  AC_MSG_RESULT(no)
fi
AC_SUBST(LN_S)dnl
])

define(AC_RSH,
[errprint(__file__:__line__: [$0] has been removed; replace it with equivalent code
)m4exit(4)])


dnl ### Checks for header files


AC_DEFUN(AC_HEADER_STDC,
[AC_REQUIRE_CPP()dnl
AC_MSG_CHECKING(for ANSI C header files)
AC_CACHE_VAL(ac_cv_header_stdc,
[AC_TRY_CPP([#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <float.h>], ac_cv_header_stdc=yes, ac_cv_header_stdc=no)

if test $ac_cv_header_stdc = yes; then
  # SunOS 4.x string.h does not declare mem*, contrary to ANSI.
AC_EGREP_HEADER(memchr, string.h, , ac_cv_header_stdc=no)
fi

if test $ac_cv_header_stdc = yes; then
  # ISC 2.0.2 stdlib.h does not declare free, contrary to ANSI.
AC_EGREP_HEADER(free, stdlib.h, , ac_cv_header_stdc=no)
fi

if test $ac_cv_header_stdc = yes; then
  # /bin/cc in Irix-4.0.5 gets non-ANSI ctype macros unless using -ansi.
AC_TRY_RUN([#include <ctype.h>
#define ISLOWER(c) ('a' <= (c) && (c) <= 'z')
#define TOUPPER(c) (ISLOWER(c) ? 'A' + ((c) - 'a') : (c))
#define XOR(e, f) (((e) && !(f)) || (!(e) && (f)))
int main () { int i; for (i = 0; i < 256; i++)
if (XOR (islower (i), ISLOWER (i)) || toupper (i) != TOUPPER (i)) exit(2);
exit (0); }
], , ac_cv_header_stdc=no, ac_cv_header_stdc=no)
fi])dnl
AC_MSG_RESULT($ac_cv_header_stdc)
if test $ac_cv_header_stdc = yes; then
  AC_DEFINE(STDC_HEADERS)
fi
])

AC_DEFUN(AC_UNISTD_H,
[AC_OBSOLETE([$0], [; instead use AC_CHECK_HEADERS(unistd.h)])dnl
AC_CHECK_HEADER(unistd.h, AC_DEFINE(HAVE_UNISTD_H))])

AC_DEFUN(AC_USG,
[AC_OBSOLETE([$0],
  [; instead use AC_CHECK_HEADERS(string.h) and HAVE_STRING_H])dnl
AC_MSG_CHECKING([for BSD string and memory functions])
AC_TRY_LINK([#include <strings.h>], [rindex(0, 0); bzero(0, 0);],
  [AC_MSG_RESULT(yes); AC_DEFINE(USG)], [AC_MSG_RESULT(no)])])


dnl If memchr and the like aren't declared in <string.h>, include <memory.h>.
dnl To avoid problems, don't check for gcc2 built-ins.
AC_DEFUN(AC_MEMORY_H,
[AC_OBSOLETE([$0], [; instead use AC_CHECK_HEADERS(memory.h) and HAVE_MEMORY_H])dnl
AC_MSG_CHECKING(whether string.h declares mem functions)
AC_EGREP_HEADER(memchr, string.h, ac_found=yes, ac_found=no)
AC_MSG_RESULT($ac_found)
if test $ac_found = no; then
  AC_CHECK_HEADER(memory.h, [AC_DEFINE(NEED_MEMORY_H)])
fi
])

AC_DEFUN(AC_HEADER_MAJOR,
[AC_MSG_CHECKING(whether sys/types.h defines makedev)
AC_CACHE_VAL(ac_cv_header_sys_types_h_makedev,
[AC_TRY_LINK([#include <sys/types.h>], [return makedev(0, 0);],
  ac_cv_header_sys_types_h_makedev=yes, ac_cv_header_sys_types_h_makedev=no)
])dnl
AC_MSG_RESULT($ac_cv_header_sys_types_h_makedev)

if test $ac_cv_header_sys_types_h_makedev = no; then
AC_CHECK_HEADER(sys/mkdev.h, [AC_DEFINE(MAJOR_IN_MKDEV)])

  if test $ac_cv_header_sys_mkdev_h = no; then
AC_CHECK_HEADER(sys/sysmacros.h, [AC_DEFINE(MAJOR_IN_SYSMACROS)])
  fi
fi
])

AC_DEFUN(AC_HEADER_DIRENT,
[ac_header_dirent=no
AC_CHECK_HEADERS_DIRENT(dirent.h sys/ndir.h sys/dir.h ndir.h,
  [ac_header_dirent=$ac_hdr; break])
# Two versions of opendir et al. are in -ldir and -lx on SCO Xenix.
if test $ac_header_dirent = dirent.h; then
AC_CHECK_LIB(dir, opendir, LIBS="$LIBS -ldir")
else
AC_CHECK_LIB(x, opendir, LIBS="$LIBS -lx")
fi
])

dnl Like AC_CHECK_HEADER, except also make sure that HEADER-FILE
dnl defines the type `DIR'.  dirent.h on NextStep 3.2 doesn't.
dnl AC_CHECK_HEADER_DIRENT(HEADER-FILE, ACTION-IF-FOUND)
AC_DEFUN(AC_CHECK_HEADER_DIRENT,
[ac_safe=`echo "$1" | tr './\055' '___'`
AC_MSG_CHECKING([for $1 that defines DIR])
AC_CACHE_VAL(ac_cv_header_dirent_$ac_safe,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <$1>], [DIR *dirp = 0;],
  eval "ac_cv_header_dirent_$ac_safe=yes",
  eval "ac_cv_header_dirent_$ac_safe=no")])dnl
if eval "test \"`echo '$ac_cv_header_dirent_'$ac_safe`\" = yes"; then
  AC_MSG_RESULT(yes)
  $2
else
  AC_MSG_RESULT(no)
fi
])

dnl Like AC_CHECK_HEADERS, except succeed only for a HEADER-FILE that
dnl defines `DIR'.
dnl AC_CHECK_HEADERS_DIRENT(HEADER-FILE... [, ACTION])
define(AC_CHECK_HEADERS_DIRENT,
[for ac_hdr in $1
do
AC_CHECK_HEADER_DIRENT($ac_hdr,
[changequote(, )dnl
  ac_tr_hdr=HAVE_`echo $ac_hdr | tr '[a-z]./\055' '[A-Z]___'`
changequote([, ])dnl
  AC_DEFINE_UNQUOTED($ac_tr_hdr) $2])dnl
done])

AC_DEFUN(AC_DIR_HEADER,
[AC_OBSOLETE([$0], [; instead use AC_HEADER_DIRENT])dnl
ac_header_dirent=no
for ac_hdr in dirent.h sys/ndir.h sys/dir.h ndir.h; do
  AC_CHECK_HEADER_DIRENT($ac_hdr, [ac_header_dirent=$ac_hdr; break])
done

case "$ac_header_dirent" in
dirent.h) AC_DEFINE(DIRENT) ;;
sys/ndir.h) AC_DEFINE(SYSNDIR) ;;
sys/dir.h) AC_DEFINE(SYSDIR) ;;
ndir.h) AC_DEFINE(NDIR) ;;
esac

AC_MSG_CHECKING(whether closedir returns void)
AC_CACHE_VAL(ac_cv_func_closedir_void,
[AC_TRY_RUN([#include <sys/types.h>
#include <$ac_header_dirent>
int closedir(); main() { exit(closedir(opendir(".")) != 0); }],
  ac_cv_func_closedir_void=no, ac_cv_func_closedir_void=yes)])dnl
AC_MSG_RESULT($ac_cv_func_closedir_void)
if test $ac_cv_func_closedir_void = yes; then
  AC_DEFINE(VOID_CLOSEDIR)
fi
])

AC_DEFUN(AC_HEADER_STAT,
[AC_MSG_CHECKING(whether stat file-mode macros are broken)
AC_CACHE_VAL(ac_cv_header_stat_broken,
[AC_EGREP_CPP([You lose], [#include <sys/types.h>
#include <sys/stat.h>
#ifdef S_ISBLK
# if S_ISBLK (S_IFDIR)
You lose.
# endif
# ifdef S_IFCHR
#  if S_ISBLK (S_IFCHR)
You lose.
#  endif
# endif
#endif

#ifdef S_ISLNK
# if S_ISLNK (S_IFREG)
You lose.
# endif
#endif

#ifdef S_ISSOCK
# if S_ISSOCK (S_IFREG)
You lose.
# endif
#endif
], ac_cv_header_stat_broken=yes, ac_cv_header_stat_broken=no)])dnl
AC_MSG_RESULT($ac_cv_header_stat_broken)
if test $ac_cv_header_stat_broken = yes; then
  AC_DEFINE(STAT_MACROS_BROKEN)
fi
])

AC_DEFUN(AC_DECL_SYS_SIGLIST,
[AC_MSG_CHECKING([for sys_siglist declaration in signal.h or unistd.h])
AC_CACHE_VAL(ac_cv_decl_sys_siglist,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <signal.h>
/* NetBSD declares sys_siglist in unistd.h.  */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif], [char *msg = *(sys_siglist + 1);],
  ac_cv_decl_sys_siglist=yes, ac_cv_decl_sys_siglist=no)])dnl
AC_MSG_RESULT($ac_cv_decl_sys_siglist)
if test $ac_cv_decl_sys_siglist = yes; then
  AC_DEFINE(SYS_SIGLIST_DECLARED)
fi
])

AC_DEFUN(AC_HEADER_SYS_WAIT,
[AC_MSG_CHECKING([for sys/wait.h that is POSIX.1 compatible])
AC_CACHE_VAL(ac_cv_header_sys_wait_h,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/wait.h>
#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)
#endif
#ifndef WIFEXITED
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)
#endif], [int s;
wait (&s);
s = WIFEXITED (s) ? WEXITSTATUS (s) : 1;],
ac_cv_header_sys_wait_h=yes, ac_cv_header_sys_wait_h=no)])dnl
AC_MSG_RESULT($ac_cv_header_sys_wait_h)
if test $ac_cv_header_sys_wait_h = yes; then
  AC_DEFINE(HAVE_SYS_WAIT_H)
fi
])


dnl ### Checks for typedefs


AC_DEFUN(AC_TYPE_GETGROUPS,
[AC_REQUIRE([AC_TYPE_UID_T])dnl
AC_MSG_CHECKING(type of array argument to getgroups)
AC_CACHE_VAL(ac_cv_type_getgroups,
[AC_TRY_RUN(
changequote(<<, >>)dnl
<<
/* Thanks to Mike Rendell for this test.  */
#include <sys/types.h>
#define NGID 256
#undef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
main()
{
  gid_t gidset[NGID];
  int i, n;
  union { gid_t gval; long lval; }  val;

  val.lval = -1;
  for (i = 0; i < NGID; i++)
    gidset[i] = val.gval;
  n = getgroups (sizeof (gidset) / MAX (sizeof (int), sizeof (gid_t)) - 1,
                 gidset);
  /* Exit non-zero if getgroups seems to require an array of ints.  This
     happens when gid_t is short but getgroups modifies an array of ints.  */
  exit ((n > 0 && gidset[n] != val.gval) ? 1 : 0);
}
>>,
changequote([, ])dnl
  ac_cv_type_getgroups=gid_t, ac_cv_type_getgroups=int,
  ac_cv_type_getgroups=cross)
if test $ac_cv_type_getgroups = cross; then
  dnl When we can't run the test program (we are cross compiling), presume
  dnl that <unistd.h> has either an accurate prototype for getgroups or none.
  dnl Old systems without prototypes probably use int.
  AC_EGREP_HEADER([getgroups.*int.*gid_t], unistd.h,
		  ac_cv_type_getgroups=gid_t, ac_cv_type_getgroups=int)
fi])dnl
AC_MSG_RESULT($ac_cv_type_getgroups)
AC_DEFINE_UNQUOTED(GETGROUPS_T, $ac_cv_type_getgroups)
])

AC_DEFUN(AC_TYPE_UID_T,
[AC_MSG_CHECKING(for uid_t in sys/types.h)
AC_CACHE_VAL(ac_cv_type_uid_t,
[AC_EGREP_HEADER(uid_t, sys/types.h,
  ac_cv_type_uid_t=yes, ac_cv_type_uid_t=no)])dnl
AC_MSG_RESULT($ac_cv_type_uid_t)
if test $ac_cv_type_uid_t = no; then
  AC_DEFINE(uid_t, int)
  AC_DEFINE(gid_t, int)
fi
])

AC_DEFUN(AC_TYPE_SIZE_T,
[AC_CHECK_TYPE(size_t, unsigned)])

AC_DEFUN(AC_TYPE_PID_T,
[AC_CHECK_TYPE(pid_t, int)])

AC_DEFUN(AC_TYPE_OFF_T,
[AC_CHECK_TYPE(off_t, long)])

AC_DEFUN(AC_TYPE_MODE_T,
[AC_CHECK_TYPE(mode_t, int)])

dnl Note that identifiers starting with SIG are reserved by ANSI C.
AC_DEFUN(AC_TYPE_SIGNAL,
[AC_MSG_CHECKING([return type of signal handlers])
AC_CACHE_VAL(ac_cv_type_signal,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <signal.h>
#ifdef signal
#undef signal
#endif
extern void (*signal ()) ();],
[int i;], ac_cv_type_signal=void, ac_cv_type_signal=int)])dnl
AC_MSG_RESULT($ac_cv_type_signal)
AC_DEFINE_UNQUOTED(RETSIGTYPE, $ac_cv_type_signal)
])


dnl ### Checks for functions


AC_DEFUN(AC_FUNC_CLOSEDIR_VOID,
[AC_REQUIRE([AC_HEADER_DIRENT])dnl
AC_MSG_CHECKING(whether closedir returns void)
AC_CACHE_VAL(ac_cv_func_closedir_void,
[AC_TRY_RUN([#include <sys/types.h>
#include <$ac_header_dirent>
int closedir(); main() { exit(closedir(opendir(".")) != 0); }],
  ac_cv_func_closedir_void=no, ac_cv_func_closedir_void=yes)])dnl
AC_MSG_RESULT($ac_cv_func_closedir_void)
if test $ac_cv_func_closedir_void = yes; then
  AC_DEFINE(CLOSEDIR_VOID)
fi
])

AC_DEFUN(AC_FUNC_MMAP,
[AC_MSG_CHECKING(for working mmap)
AC_CACHE_VAL(ac_cv_func_mmap,
[AC_TRY_RUN([
/* Thanks to Mike Haertel and Jim Avera for this test. */
#include <sys/types.h>
#include <fcntl.h>
#include <sys/mman.h>

#ifdef BSD
# ifndef BSD4_1
#  define HAVE_GETPAGESIZE
# endif
#endif

#ifndef HAVE_GETPAGESIZE
# include <sys/param.h>
# ifdef EXEC_PAGESIZE
#  define getpagesize() EXEC_PAGESIZE
# else
#  ifdef NBPG
#   define getpagesize() NBPG * CLSIZE
#   ifndef CLSIZE
#    define CLSIZE 1
#   endif
#  else
#   ifdef NBPC
#    define getpagesize() NBPC
#   else
#    define getpagesize() PAGESIZE /* SVR4 */
#   endif
#  endif
# endif
#endif

#ifdef __osf__
# define valloc malloc
#endif

#ifdef __cplusplus
extern "C" { void *valloc(unsigned), *malloc(unsigned); }
#else
char *valloc(), *malloc();
#endif

int
main()
{
  char *buf1, *buf2, *buf3;
  int i = getpagesize(), j;
  int i2 = getpagesize()*2;
  int fd;

  buf1 = (char *)valloc(i2);
  buf2 = (char *)valloc(i);
  buf3 = (char *)malloc(i2);
  for (j = 0; j < i2; ++j)
    *(buf1 + j) = rand();
  fd = open("conftestmmap", O_CREAT | O_RDWR, 0666);
  write(fd, buf1, i2);
  mmap(buf2, i, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE, fd, 0);
  for (j = 0; j < i; ++j)
    if (*(buf1 + j) != *(buf2 + j))
      exit(1);
  lseek(fd, (long)i, 0);
  read(fd, buf2, i); /* read into mapped memory -- file should not change */
  /* (it does in i386 SVR4.0 - Jim Avera, jima@netcom.com) */
  lseek(fd, (long)0, 0);
  read(fd, buf3, i2);
  for (j = 0; j < i2; ++j)
    if (*(buf1 + j) != *(buf3 + j))
      exit(1);
  exit(0);
}
], ac_cv_func_mmap=yes, ac_cv_func_mmap=no, ac_cv_func_mmap=no)])dnl
AC_MSG_RESULT($ac_cv_func_mmap)
if test $ac_cv_func_mmap = yes; then
  AC_DEFINE(HAVE_MMAP)
fi
])

AC_DEFUN(AC_FUNC_VPRINTF,
[AC_CHECK_FUNC(vprintf, AC_DEFINE(HAVE_VPRINTF))
if test "$ac_cv_func_vprintf" != yes; then
AC_CHECK_FUNC(_doprnt, AC_DEFINE(HAVE_DOPRNT))
fi
])

AC_DEFUN(AC_FUNC_VFORK,
[AC_REQUIRE([AC_TYPE_PID_T])dnl
AC_CHECK_HEADER(vfork.h, AC_DEFINE(HAVE_VFORK_H))
AC_MSG_CHECKING(for working vfork)
AC_CACHE_VAL(ac_cv_func_vfork,
[AC_REQUIRE([AC_TYPE_SIGNAL])
AC_TRY_RUN([/* Thanks to Paul Eggert for this test.  */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_VFORK_H
#include <vfork.h>
#endif
/* On sparc systems, changes by the child to local and incoming
   argument registers are propagated back to the parent.
   The compiler is told about this with #include <vfork.h>,
   but some compilers (e.g. gcc -O) don't grok <vfork.h>.
   Test for this by using a static variable whose address
   is put into a register that is clobbered by the vfork.  */
static
#ifdef __cplusplus
sparc_address_test (int arg)
#else
sparc_address_test (arg) int arg;
#endif
{
  static pid_t child;
  if (!child) {
    child = vfork ();
    if (child < 0)
      perror ("vfork");
    if (!child) {
      arg = getpid();
      write(-1, "", 0);
      _exit (arg);
    }
  }
}
static int signalled;
static RETSIGTYPE catch (s) int s; { signalled = 1; }
main() {
  pid_t parent = getpid ();
  pid_t child;

  sparc_address_test ();

  signal (SIGINT, catch);

  child = vfork ();

  if (child == 0) {
    /* Here is another test for sparc vfork register problems.
       This test uses lots of local variables, at least
       as many local variables as main has allocated so far
       including compiler temporaries.  4 locals are enough for
       gcc 1.40.3 on a sparc, but we use 8 to be safe.
       A buggy compiler should reuse the register of parent
       for one of the local variables, since it will think that
       parent can't possibly be used any more in this routine.
       Assigning to the local variable will thus munge parent
       in the parent process.  */
    pid_t
      p = getpid(), p1 = getpid(), p2 = getpid(), p3 = getpid(),
      p4 = getpid(), p5 = getpid(), p6 = getpid(), p7 = getpid();
    /* Convince the compiler that p..p7 are live; otherwise, it might
       use the same hardware register for all 8 local variables.  */
    if (p != p1 || p != p2 || p != p3 || p != p4
	|| p != p5 || p != p6 || p != p7)
      _exit(1);

    /* On some systems (e.g. SunOS 5.2), if the parent is catching
       a signal, the child ignores the signal before execing,
       and the parent later receives that signal, the parent dumps core.
       Test for this by ignoring SIGINT in the child.  */
    signal (SIGINT, SIG_IGN);

    /* On some systems (e.g. IRIX 3.3),
       vfork doesn't separate parent from child file descriptors.
       If the child closes a descriptor before it execs or exits,
       this munges the parent's descriptor as well.
       Test for this by closing stdout in the child.  */
    _exit(close(fileno(stdout)) != 0);
  } else {
    int status;
    struct stat st;

    while (wait(&status) != child)
      ;
    exit(
	 /* Was there some problem with vforking?  */
	 child < 0

	 /* Did the child fail?  (This shouldn't happen.)  */
	 || status

	 /* Did the vfork/compiler bug occur?  */
	 || parent != getpid()

	 /* Did the signal handling bug occur?  */
	 || kill(parent, SIGINT) != 0
	 || signalled != 1

	 /* Did the file descriptor bug occur?  */
	 || fstat(fileno(stdout), &st) != 0
	 );
  }
}], ac_cv_func_vfork=yes, ac_cv_func_vfork=no, ac_cv_func_vfork=no)])dnl
AC_MSG_RESULT($ac_cv_func_vfork)
if test $ac_cv_func_vfork = no; then
  AC_DEFINE(vfork, fork)
fi
])

AC_DEFUN(AC_FUNC_WAIT3,
[AC_MSG_CHECKING(for wait3 that fills in rusage)
AC_CACHE_VAL(ac_cv_func_wait3,
[AC_TRY_RUN([#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
/* HP-UX has wait3 but does not fill in rusage at all.  */
main() {
  struct rusage r;
  int i;
  /* Use a field that we can force nonzero --
     voluntary context switches.
     For systems like NeXT and OSF/1 that don't set it,
     also use the system CPU time.  */
  r.ru_nvcsw = 0;
  r.ru_stime.tv_sec = 0;
  r.ru_stime.tv_usec = 0;
  switch (fork()) {
  case 0: /* Child.  */
    sleep(1); /* Give up the CPU.  */
    _exit(0);
  case -1: _exit(0); /* What can we do?  */
  default: /* Parent.  */
    wait3(&i, 0, &r);
    sleep(1); /* Avoid "text file busy" from rm on fast HP-UX machines.  */
    exit(r.ru_nvcsw == 0
	 && r.ru_stime.tv_sec == 0 && r.ru_stime.tv_usec == 0);
  }
}], ac_cv_func_wait3=yes, ac_cv_func_wait3=no, ac_cv_func_wait3=no)])dnl
AC_MSG_RESULT($ac_cv_func_wait3)
if test $ac_cv_func_wait3 = yes; then
  AC_DEFINE(HAVE_WAIT3)
fi
])

AC_DEFUN(AC_FUNC_ALLOCA,
[AC_REQUIRE_CPP()dnl Set CPP; we run AC_EGREP_CPP conditionally.
# The Ultrix 4.2 mips builtin alloca declared by alloca.h only works
# for constant arguments.  Useless!
AC_MSG_CHECKING([for working alloca.h])
AC_CACHE_VAL(ac_cv_header_alloca_h,
[AC_TRY_LINK([#include <alloca.h>], [char *p = alloca(2 * sizeof(int));],
  ac_cv_header_alloca_h=yes, ac_cv_header_alloca_h=no)])dnl
AC_MSG_RESULT($ac_cv_header_alloca_h)
if test $ac_cv_header_alloca_h = yes; then
  AC_DEFINE(HAVE_ALLOCA_H)
fi

AC_MSG_CHECKING([for alloca])
AC_CACHE_VAL(ac_cv_func_alloca,
[AC_TRY_LINK([
#ifdef __GNUC__
# define alloca __builtin_alloca
#else
# if HAVE_ALLOCA_H
#  include <alloca.h>
# else
#  ifdef _AIX
 #pragma alloca
#  else
#   ifndef alloca /* predefined by HP cc +Olibcalls */
char *alloca ();
#   endif
#  endif
# endif
#endif
], [char *p = (char *) alloca(1);],
  ac_cv_func_alloca=yes, ac_cv_func_alloca=no)])dnl
AC_MSG_RESULT($ac_cv_func_alloca)
if test $ac_cv_func_alloca = yes; then
  AC_DEFINE(HAVE_ALLOCA)
fi

if test $ac_cv_func_alloca = no; then
  # The SVR3 libPW and SVR4 libucb both contain incompatible functions
  # that cause trouble.  Some versions do not even contain alloca or
  # contain a buggy version.  If you still want to use their alloca,
  # use ar to extract alloca.o from them instead of compiling alloca.c.
  ALLOCA=alloca.o
  AC_DEFINE(C_ALLOCA)

AC_MSG_CHECKING(whether alloca needs Cray hooks)
AC_CACHE_VAL(ac_cv_os_cray,
[AC_EGREP_CPP(webecray,
[#if defined(CRAY) && ! defined(CRAY2)
webecray
#else
wenotbecray
#endif
], ac_cv_os_cray=yes, ac_cv_os_cray=no)])dnl
AC_MSG_RESULT($ac_cv_os_cray)
if test $ac_cv_os_cray = yes; then
AC_CHECK_FUNC(_getb67, AC_DEFINE(CRAY_STACKSEG_END, _getb67),
AC_CHECK_FUNC(GETB67, AC_DEFINE(CRAY_STACKSEG_END, GETB67),
AC_CHECK_FUNC(getb67, AC_DEFINE(CRAY_STACKSEG_END, getb67))))
fi

AC_MSG_CHECKING(stack direction for C alloca)
AC_CACHE_VAL(ac_cv_c_stack_direction,
[AC_TRY_RUN([find_stack_direction ()
{
  static char *addr = 0;
  auto char dummy;
  if (addr == 0)
    {
      addr = &dummy;
      return find_stack_direction ();
    }
  else
    return (&dummy > addr) ? 1 : -1;
}
main ()
{
  exit (find_stack_direction() < 0);
}], ac_cv_c_stack_direction=1, ac_cv_c_stack_direction=-1,
  ac_cv_c_stack_direction=0)])dnl
AC_MSG_RESULT($ac_cv_c_stack_direction)
AC_DEFINE_UNQUOTED(STACK_DIRECTION, $ac_cv_c_stack_direction)
fi
AC_SUBST(ALLOCA)dnl
])

AC_DEFUN(AC_FUNC_GETLOADAVG,
[# Some definitions of getloadavg require that the program be installed setgid.
NEED_SETGID=false
AC_SUBST(NEED_SETGID)dnl
ac_have_func=no

# Check for the 4.4BSD definition of getloadavg.
AC_CHECK_LIB(util, getloadavg, [LIBS="$LIBS -lutil" ac_have_func=yes
# Some systems with -lutil have (and need) -lkvm as well, some do not.
AC_CHECK_LIB(kvm, kvm_open,  LIBS="$LIBS -lkvm")])

if test $ac_have_func = no; then
# There is a commonly available library for RS/6000 AIX.
# Since it is not a standard part of AIX, it might be installed locally.
ac_save_LIBS="$LIBS" LIBS="-L/usr/local/lib $LIBS"
AC_CHECK_LIB(getloadavg, getloadavg, LIBS="$LIBS -lgetloadavg", LIBS="$ac_save_LIBS")
fi

# Make sure it is really in the library, if we think we found it.
AC_REPLACE_FUNCS(getloadavg)

if test $ac_cv_func_getloadavg = yes; then
  AC_DEFINE(HAVE_GETLOADAVG)
else
ac_have_func=no
AC_CHECK_HEADER(sys/dg_sys_info.h,
[ac_have_func=yes AC_DEFINE(DGUX)
AC_CHECK_LIB(dgc, dg_sys_info)])
if test $ac_have_func = no; then
# We cannot check for <dwarf.h>, because Solaris 2 does not use dwarf (it
# uses stabs), but it is still SVR4.  We cannot check for <elf.h> because
# Irix 4.0.5F has the header but not the library.
AC_CHECK_LIB(elf, elf_read,
  [LIBS="$LIBS -lelf" ac_have_func=yes AC_DEFINE(SVR4)
  AC_CHECK_LIB(kvm, kvm_open, LIBS="$LIBS -lkvm")])
fi
if test $ac_have_func = no; then
AC_CHECK_HEADER(inq_stats/cpustats.h,
  [ac_have_func=yes AC_DEFINE(UMAX)
   AC_DEFINE(UMAX4_3)])
fi
if test $ac_have_func = no; then
AC_CHECK_HEADER(sys/cpustats.h,
  [ac_have_func=yes AC_DEFINE(UMAX)])
fi
if test $ac_have_func = no; then
AC_CHECK_HEADERS(mach/mach.h)
fi

AC_CHECK_HEADER(nlist.h,
[AC_DEFINE(NLIST_STRUCT)
AC_MSG_CHECKING([for n_un in struct nlist])
AC_CACHE_VAL(ac_cv_struct_nlist_n_un,
[AC_TRY_COMPILE([#include <nlist.h>],
[struct nlist n; n.n_un.n_name = 0;],
ac_cv_struct_nlist_n_un=yes, ac_cv_struct_nlist_n_un=no)])dnl
AC_MSG_RESULT($ac_cv_struct_nlist_n_un)
if test $ac_cv_struct_nlist_n_un = yes; then
  AC_DEFINE(NLIST_NAME_UNION)
fi
])dnl

dnl FIXME two bugs here:
dnl Hardwiring the path of getloadavg.c in the top-level directory,
dnl and not checking whether a getloadavg from a library needs privileges.
AC_MSG_CHECKING(whether getloadavg requires setgid)
AC_CACHE_VAL(ac_cv_func_getloadavg_setgid,
[AC_EGREP_CPP([Yowza Am I SETGID yet],
[#include "$srcdir/getloadavg.c"
#ifdef LDAV_PRIVILEGED
Yowza Am I SETGID yet
#endif],
  ac_cv_func_getloadavg_setgid=yes, ac_cv_func_getloadavg_setgid=no)])dnl
AC_MSG_RESULT($ac_cv_func_getloadavg_setgid)
if test $ac_cv_func_getloadavg_setgid = yes; then
  NEED_SETGID=true AC_DEFINE(GETLOADAVG_PRIVILEGED)
fi

fi # Do not have getloadavg in system libraries.

if test "$NEED_SETGID" = true; then
  AC_MSG_CHECKING(group of /dev/kmem)
AC_CACHE_VAL(ac_cv_group_kmem,
[changequote(, )dnl
  # On Solaris, /dev/kmem is a symlink.  Get info on the real file.
  ac_ls_output=`ls -lgL /dev/kmem 2>/dev/null`
  # If we got an error (system does not support symlinks), try without -L.
  test -z "$ac_ls_output" && ac_ls_output=`ls -lg /dev/kmem`
  ac_cv_group_kmem=`echo $ac_ls_output \
    | sed -ne 's/[ 	][ 	]*/ /g;
	       s/^.[sSrwx-]* *[0-9]* *\([^0-9]*\)  *.*/\1/;
	       / /s/.* //;p;'`
changequote([, ])dnl
])dnl
  KMEM_GROUP=$ac_cv_group_kmem
  AC_MSG_RESULT($KMEM_GROUP)
fi
AC_SUBST(KMEM_GROUP)dnl
])

AC_DEFUN(AC_FUNC_UTIME_NULL,
[AC_MSG_CHECKING(whether utime accepts a null argument)
AC_CACHE_VAL(ac_cv_func_utime_null,
[rm -f conftestdata; > conftestdata
# Sequent interprets utime(file, 0) to mean use start of epoch.  Wrong.
AC_TRY_RUN([#include <sys/types.h>
#include <sys/stat.h>
main() {
struct stat s, t;
exit(!(stat ("conftestdata", &s) == 0 && utime("conftestdata", (long *)0) == 0
&& stat("conftestdata", &t) == 0 && t.st_mtime >= s.st_mtime
&& t.st_mtime - s.st_mtime < 120));
}], ac_cv_func_utime_null=yes, ac_cv_func_utime_null=no,
  ac_cv_func_utime_null=no)
rm -f core])dnl
AC_MSG_RESULT($ac_cv_func_utime_null)
if test $ac_cv_func_utime_null = yes; then
  AC_DEFINE(HAVE_UTIME_NULL)
fi
])

AC_DEFUN(AC_FUNC_STRCOLL,
[AC_MSG_CHECKING(for strcoll)
AC_CACHE_VAL(ac_cv_func_strcoll,
[AC_TRY_RUN([#include <string.h>
main ()
{
  exit (strcoll ("abc", "def") >= 0 ||
	strcoll ("ABC", "DEF") >= 0 ||
	strcoll ("123", "456") >= 0);
}], ac_cv_func_strcoll=yes, ac_cv_func_strcoll=no, ac_cv_func_strcoll=no)])dnl
AC_MSG_RESULT($ac_cv_func_strcoll)
if test $ac_cv_func_strcoll = yes; then
  AC_DEFINE(HAVE_STRCOLL)
fi
])

AC_DEFUN(AC_FUNC_SETVBUF_REVERSED,
[AC_MSG_CHECKING(whether setvbuf arguments are reversed)
AC_CACHE_VAL(ac_cv_func_setvbuf_reversed,
[AC_TRY_RUN([#include <stdio.h>
/* If setvbuf has the reversed format, exit 0. */
main () {
  /* This call has the arguments reversed.
     A reversed system may check and see that the address of main
     is not _IOLBF, _IONBF, or _IOFBF, and return nonzero.  */
  if (setvbuf(stdout, _IOLBF, (char *) main, BUFSIZ) != 0)
    exit(1);
  putc('\r', stdout);
  exit(0);			/* Non-reversed systems segv here.  */
}], ac_cv_func_setvbuf_reversed=yes, ac_cv_func_setvbuf_reversed=no)
rm -f core])dnl
AC_MSG_RESULT($ac_cv_func_setvbuf_reversed)
if test $ac_cv_func_setvbuf_reversed = yes; then
  AC_DEFINE(SETVBUF_REVERSED)
fi
])

AC_DEFUN(AC_FUNC_GETMNTENT,
[# getmntent is in -lsun on Irix 4, -lseq on Dynix/PTX.
AC_CHECK_LIB(sun, getmntent, LIBS="$LIBS -lsun",
  [AC_CHECK_LIB(seq, getmntent, LIBS="$LIBS -lseq")])
AC_CHECK_FUNC(getmntent, [AC_DEFINE(HAVE_GETMNTENT)])])

AC_DEFUN(AC_FUNC_STRFTIME,
[# strftime is in -lintl on SCO UNIX.
AC_CHECK_LIB(intl, strftime, LIBS="$LIBS -lintl")
AC_CHECK_FUNC(strftime, [AC_DEFINE(HAVE_STRFTIME)])])

AC_DEFUN(AC_FUNC_MEMCMP,
[AC_MSG_CHECKING(for 8-bit clean memcmp)
AC_CACHE_VAL(ac_cv_func_memcmp,
[AC_TRY_RUN([
main()
{
  char c0 = 0x40, c1 = 0x80, c2 = 0x81;
  exit(memcmp(&c0, &c2, 1) < 0 && memcmp(&c1, &c2, 1) < 0 ? 0 : 1);
}
], ac_cv_func_memcmp=yes, ac_cv_func_memcmp=no, ac_cv_func_memcmp=no)])dnl
AC_MSG_RESULT($ac_cv_func_memcmp)
test $ac_cv_func_memcmp = no && LIBOBJS="$LIBOBJS memcmp.o"
AC_SUBST(LIBOBJS)dnl
])


dnl ### Checks for structure members


AC_DEFUN(AC_HEADER_TIME,
[AC_MSG_CHECKING([whether time.h and sys/time.h may both be included])
AC_CACHE_VAL(ac_cv_header_time,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/time.h>
#include <time.h>],
[struct tm *tp;], ac_cv_header_time=yes, ac_cv_header_time=no)])dnl
AC_MSG_RESULT($ac_cv_header_time)
if test $ac_cv_header_time = yes; then
  AC_DEFINE(TIME_WITH_SYS_TIME)
fi
])

AC_DEFUN(AC_STRUCT_TM,
[AC_MSG_CHECKING([whether struct tm is in sys/time.h or time.h])
AC_CACHE_VAL(ac_cv_struct_tm,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <time.h>],
[struct tm *tp; tp->tm_sec;],
  ac_cv_struct_tm=time.h, ac_cv_struct_tm=sys/time.h)])dnl
AC_MSG_RESULT($ac_cv_struct_tm)
if test $ac_cv_struct_tm = sys/time.h; then
  AC_DEFINE(TM_IN_SYS_TIME)
fi
])

AC_DEFUN(AC_STRUCT_TIMEZONE,
[AC_REQUIRE([AC_STRUCT_TM])dnl
AC_MSG_CHECKING([for tm_zone in struct tm])
AC_CACHE_VAL(ac_cv_struct_tm_zone,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <$ac_cv_struct_tm>], [struct tm tm; tm.tm_zone;],
  ac_cv_struct_tm_zone=yes, ac_cv_struct_tm_zone=no)])dnl
AC_MSG_RESULT($ac_cv_struct_tm_zone)
if test "$ac_cv_struct_tm_zone" = yes; then
  AC_DEFINE(HAVE_TM_ZONE)
else
  AC_MSG_CHECKING([for tzname])
AC_CACHE_VAL(ac_cv_var_tzname,
[AC_TRY_LINK(
changequote(<<, >>)dnl
<<#include <time.h>
#ifndef tzname /* For SGI.  */
extern char *tzname[]; /* RS6000 and others reject char **tzname.  */
#endif>>,
changequote([, ])dnl
[atoi(*tzname);], ac_cv_var_tzname=yes, ac_cv_var_tzname=no)])dnl
  AC_MSG_RESULT($ac_cv_var_tzname)
  if test $ac_cv_var_tzname = yes; then
    AC_DEFINE(HAVE_TZNAME)
  fi
fi
])

AC_DEFUN(AC_STRUCT_ST_BLOCKS,
[AC_MSG_CHECKING([for st_blocks in struct stat])
AC_CACHE_VAL(ac_cv_struct_st_blocks,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/stat.h>], [struct stat s; s.st_blocks;],
ac_cv_struct_st_blocks=yes, ac_cv_struct_st_blocks=no)])dnl
AC_MSG_RESULT($ac_cv_struct_st_blocks)
if test $ac_cv_struct_st_blocks = yes; then
  AC_DEFINE(HAVE_ST_BLOCKS)
else
  LIBOBJS="$LIBOBJS fileblocks.o"
fi
AC_SUBST(LIBOBJS)dnl
])

AC_DEFUN(AC_STRUCT_ST_BLKSIZE,
[AC_MSG_CHECKING([for st_blksize in struct stat])
AC_CACHE_VAL(ac_cv_struct_st_blksize,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/stat.h>], [struct stat s; s.st_blksize;],
ac_cv_struct_st_blksize=yes, ac_cv_struct_st_blksize=no)])dnl
AC_MSG_RESULT($ac_cv_struct_st_blksize)
if test $ac_cv_struct_st_blksize = yes; then
  AC_DEFINE(HAVE_ST_BLKSIZE)
fi
])

AC_DEFUN(AC_STRUCT_ST_RDEV,
[AC_MSG_CHECKING([for st_rdev in struct stat])
AC_CACHE_VAL(ac_cv_struct_st_rdev,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/stat.h>], [struct stat s; s.st_rdev;],
ac_cv_struct_st_rdev=yes, ac_cv_struct_st_rdev=no)])dnl
AC_MSG_RESULT($ac_cv_struct_st_rdev)
if test $ac_cv_struct_st_rdev = yes; then
  AC_DEFINE(HAVE_ST_RDEV)
fi
])


dnl ### Checks for compiler characteristics


AC_DEFUN(AC_C_CROSS,
[# If we cannot run a trivial program, we must be cross compiling.
AC_MSG_CHECKING(whether cross-compiling)
AC_CACHE_VAL(ac_cv_c_cross,
[AC_TRY_RUN([main(){return(0);}],
  ac_cv_c_cross=no, ac_cv_c_cross=yes, ac_cv_cross=yes)])dnl
cross_compiling=$ac_cv_c_cross
AC_MSG_RESULT($ac_cv_c_cross)
])

AC_DEFUN(AC_C_CHAR_UNSIGNED,
[AC_MSG_CHECKING(whether char is unsigned)
AC_CACHE_VAL(ac_cv_c_char_unsigned,
[if test "$GCC" = yes; then
  # GCC predefines this symbol on systems where it applies.
AC_EGREP_CPP(yes,
[#ifdef __CHAR_UNSIGNED__
  yes
#endif
], ac_cv_c_char_unsigned=yes, ac_cv_c_char_unsigned=no)
else
AC_TRY_RUN(
[/* volatile prevents gcc2 from optimizing the test away on sparcs.  */
#if !defined(__STDC__) || __STDC__ != 1
#define volatile
#endif
main() {
  volatile char c = 255; exit(c < 0);
}], ac_cv_c_char_unsigned=yes, ac_cv_c_char_unsigned=no)
fi])dnl
AC_MSG_RESULT($ac_cv_c_char_unsigned)
if test $ac_cv_c_char_unsigned = yes && test "$GCC" != yes; then
  AC_DEFINE(__CHAR_UNSIGNED__)
fi
])

AC_DEFUN(AC_C_LONG_DOUBLE,
[AC_MSG_CHECKING(for long double)
AC_CACHE_VAL(ac_cv_c_long_double,
[if test "$GCC" = yes; then
  ac_cv_c_long_double=yes
else
AC_TRY_RUN([int main() {
/* The Stardent Vistra knows sizeof(long double), but does not support it.  */
long double foo = 0.0;
/* On Ultrix 4.3 cc, long double is 4 and double is 8.  */
exit(sizeof(long double) < sizeof(double)); }],
ac_cv_c_long_double=yes, ac_cv_c_long_double=no)
fi])dnl
AC_MSG_RESULT($ac_cv_c_long_double)
if test $ac_cv_c_long_double = yes; then
  AC_DEFINE(HAVE_LONG_DOUBLE)
fi
])

AC_DEFUN(AC_INT_16_BITS,
[AC_OBSOLETE([$0], [; instead use AC_CHECK_SIZEOF(int)])dnl
AC_MSG_CHECKING(whether int is 16 bits)
AC_TRY_RUN([main() { exit(sizeof(int) != 2); }],
 [AC_MSG_RESULT(yes)
 AC_DEFINE(INT_16_BITS)], AC_MSG_RESULT(no))
])

AC_DEFUN(AC_LONG_64_BITS,
[AC_OBSOLETE([$0], [; instead use AC_CHECK_SIZEOF(long)])dnl
AC_MSG_CHECKING(whether long int is 64 bits)
AC_TRY_RUN([main() { exit(sizeof(long int) != 8); }],
 [AC_MSG_RESULT(yes)
 AC_DEFINE(LONG_64_BITS)], AC_MSG_RESULT(no))
])

AC_DEFUN(AC_C_BIGENDIAN,
[AC_MSG_CHECKING(whether byte ordering is bigendian)
AC_CACHE_VAL(ac_cv_c_bigendian,
[AC_TRY_RUN([main () {
  /* Are we little or big endian?  From Harbison&Steele.  */
  union
  {
    long l;
    char c[sizeof (long)];
  } u;
  u.l = 1;
  exit (u.c[sizeof (long) - 1] == 1);
}], ac_cv_c_bigendian=no, ac_cv_c_bigendian=yes)])dnl
AC_MSG_RESULT($ac_cv_c_bigendian)
if test $ac_cv_c_bigendian = yes; then
  AC_DEFINE(WORDS_BIGENDIAN)
fi
])

AC_DEFUN(AC_C_INLINE,
[AC_MSG_CHECKING([for inline])
AC_CACHE_VAL(ac_cv_c_inline,
[if test "$GCC" = yes; then
AC_TRY_COMPILE(, [} inline foo() {], ac_cv_c_inline=yes, ac_cv_c_inline=no)
else
  ac_cv_c_inline=no
fi])dnl
AC_MSG_RESULT($ac_cv_c_inline)
if test $ac_cv_c_inline = no; then
  AC_DEFINE(inline, __inline)
fi
])

AC_DEFUN(AC_C_CONST,
[dnl This message is consistent in form with the other checking messages,
dnl and with the result message.
AC_MSG_CHECKING([for working const])
AC_CACHE_VAL(ac_cv_c_const,
[AC_TRY_COMPILE(,
changequote(<<, >>)dnl
<<
/* Ultrix mips cc rejects this.  */
typedef int charset[2]; const charset x;
/* SunOS 4.1.1 cc rejects this.  */
char const *const *ccp;
char **p;
/* NEC SVR4.0.2 mips cc rejects this.  */
struct point {int x, y;};
static struct point const zero;
/* AIX XL C 1.02.0.0 rejects this.
   It does not let you subtract one const X* pointer from another in an arm
   of an if-expression whose if-part is not a constant expression */
const char *g = "string";
ccp = &g + (g ? g-g : 0);
/* HPUX 7.0 cc rejects these. */
++ccp;
p = (char**) ccp;
ccp = (char const *const *) p;
{ /* SCO 3.2v4 cc rejects this.  */
  char *t;
  char const *s = 0 ? (char *) 0 : (char const *) 0;

  *t++ = 0;
}
{ /* Someone thinks the Sun supposedly-ANSI compiler will reject this.  */
  int x[] = {25, 17};
  const int *foo = &x[0];
  ++foo;
}
{ /* Sun SC1.0 ANSI compiler rejects this -- but not the above. */
  typedef const int *iptr;
  iptr p = 0;
  ++p;
}
{ /* AIX XL C 1.02.0.0 rejects this saying
     "k.c", line 2.27: 1506-025 (S) Operand must be a modifiable lvalue. */
  struct s { int j; const int *ap[3]; };
  struct s *b; b->j = 5;
}
{ /* ULTRIX-32 V3.1 (Rev 9) vcc rejects this */
  const int foo = 10;
}
>>,
changequote([, ])dnl
ac_cv_c_const=yes, ac_cv_c_const=no)])dnl
AC_MSG_RESULT($ac_cv_c_const)
if test $ac_cv_c_const = no; then
  AC_DEFINE(const, )
fi
])

define(AC_ARG_ARRAY,
[errprint(__file__:__line__: [$0] has been removed; don't do unportable things with arguments
)m4exit(4)])


dnl ### Checks for operating system services


AC_DEFUN(AC_SYS_INTERPRETER,
[# Pull the hash mark out of the macro call to avoid m4 problems.
ac_msg="whether #! works in shell scripts"
AC_MSG_CHECKING($ac_msg)
AC_CACHE_VAL(ac_cv_sys_interpreter,
[echo '#!/bin/cat
exit 69
' > conftest
chmod u+x conftest
(SHELL=/bin/sh; export SHELL; ./conftest >/dev/null)
if test $? -ne 69; then
   ac_cv_sys_interpreter=yes
else
   ac_cv_sys_interpreter=no
fi
rm -f conftest])dnl
AC_MSG_RESULT($ac_cv_sys_interpreter)
])

define(AC_HAVE_POUNDBANG,
[errprint(__file__:__line__: [$0 has been replaced by AC_SYS_INTERPRETER, taking no arguments
])m4exit(4)])

AC_DEFUN(AC_SYS_LONG_FILE_NAMES,
[AC_MSG_CHECKING(for long file names)
AC_CACHE_VAL(ac_cv_sys_long_file_names,
[ac_cv_sys_long_file_names=yes
# Test for long file names in all the places we know might matter:
#      .		the current directory, where building will happen
#      /tmp		where it might want to write temporary files
#      /var/tmp		likewise
#      /usr/tmp		likewise
#      $prefix/lib	where we will be installing things
#      $exec_prefix/lib	likewise
# eval it to expand exec_prefix.
for ac_dir in `eval echo . /tmp /var/tmp /usr/tmp $prefix/lib $exec_prefix/lib` ; do
  test -d $ac_dir || continue
  test -w $ac_dir || continue # It is less confusing to not echo anything here.
  (echo 1 > $ac_dir/conftest9012345) 2>/dev/null
  (echo 2 > $ac_dir/conftest9012346) 2>/dev/null
  val=`cat $ac_dir/conftest9012345 2>/dev/null`
  if test ! -f $ac_dir/conftest9012345 || test "$val" != 1; then
    ac_cv_sys_long_file_names=no
    rm -f $ac_dir/conftest9012345 $ac_dir/conftest9012346 2>/dev/null
    break
  fi
  rm -f $ac_dir/conftest9012345 $ac_dir/conftest9012346 2>/dev/null
done])dnl
AC_MSG_RESULT($ac_cv_sys_long_file_names)
if test $ac_cv_sys_long_file_names = yes; then
  AC_DEFINE(HAVE_LONG_FILE_NAMES)
fi
])

AC_DEFUN(AC_SYS_RESTARTABLE_SYSCALLS,
[AC_MSG_CHECKING(for restartable system calls)
AC_CACHE_VAL(ac_cv_sys_restartable_syscalls,
[AC_TRY_RUN(
[/* Exit 0 (true) if wait returns something other than -1,
   i.e. the pid of the child, which means that wait was restarted
   after getting the signal.  */
#include <sys/types.h>
#include <signal.h>
ucatch (isig) { }
main () {
  int i = fork (), status;
  if (i == 0) { sleep (3); kill (getppid (), SIGINT); sleep (3); exit (0); }
  signal (SIGINT, ucatch);
  status = wait(&i);
  if (status == -1) wait(&i);
  exit (status == -1);
}
], ac_cv_sys_restartable_syscalls=yes, ac_cv_sys_restartable_syscalls=no)])dnl
AC_MSG_RESULT($ac_cv_sys_restartable_syscalls)
if test $ac_cv_sys_restartable_syscalls = yes; then
  AC_DEFINE(HAVE_RESTARTABLE_SYSCALLS)
fi
])

AC_DEFUN(AC_PATH_X,
[AC_REQUIRE_CPP()dnl Set CPP; we run AC_PATH_X_DIRECT conditionally.
# If we find X, set shell vars x_includes and x_libraries to the
# paths, otherwise set no_x=yes.
# Uses ac_ vars as temps to allow command line to override cache and checks.
# --without-x overrides everything else, but does not touch the cache.
AC_MSG_CHECKING(for X)

AC_ARG_WITH(x, [  --with-x                use the X Window System])
if test "x$with_x" = xno; then
  no_x=yes
else
  if test "x$x_includes" != xNONE && test "x$x_libraries" != xNONE; then
    no_x=
  else
AC_CACHE_VAL(ac_cv_path_x,
[# One or both of the vars are not set, and there is no cached value.
no_x=yes
AC_PATH_X_XMKMF
if test "$no_x" = yes; then
AC_PATH_X_DIRECT
fi
if test "$no_x" = yes; then
  ac_cv_path_x="no_x=yes"
else
  ac_cv_path_x="no_x= ac_x_includes=$ac_x_includes ac_x_libraries=$ac_x_libraries"
fi])dnl
  fi
  eval "$ac_cv_path_x"
fi # $with_x != no

if test "$no_x" = yes; then
  AC_MSG_RESULT(no)
else
  test "x$x_includes" = xNONE && x_includes=$ac_x_includes
  test "x$x_libraries" = xNONE && x_libraries=$ac_x_libraries
  ac_cv_path_x="no_x= ac_x_includes=$x_includes ac_x_libraries=$x_libraries"
  AC_MSG_RESULT([libraries $x_libraries, headers $x_includes])
fi
])

dnl Internal subroutine of AC_PATH_X.
dnl Set ac_x_includes, ac_x_libraries, and no_x (initially yes).
AC_DEFUN(AC_PATH_X_XMKMF,
[rm -fr conftestdir
if mkdir conftestdir; then
  cd conftestdir
  # Make sure to not put "make" in the Imakefile rules, since we grep it out.
  cat > Imakefile <<'EOF'
acfindx:
	@echo 'ac_im_incroot="${INCROOT}"; ac_im_usrlibdir="${USRLIBDIR}"; ac_im_libdir="${LIBDIR}"'
EOF
  if (xmkmf) >/dev/null 2>/dev/null && test -f Makefile; then
    no_x=
    # GNU make sometimes prints "make[1]: Entering...", which would confuse us.
    eval `make acfindx 2>/dev/null | grep -v make`
    # Open Windows xmkmf reportedly sets LIBDIR instead of USRLIBDIR.
    if test ! -f $ac_im_usrlibdir/libX11.a && test -f $ac_im_libdir/libX11.a
    then
      ac_im_usrlibdir=$ac_im_libdir
    fi
    case "$ac_im_incroot" in
	/usr/include) ;;
	*) ac_x_includes="$ac_im_incroot" ;;
    esac
    case "$ac_im_usrlibdir" in
	/usr/lib | /lib) ;;
	*) ac_x_libraries="$ac_im_usrlibdir" ;;
    esac
  fi
  cd ..
  rm -fr conftestdir
fi
])

dnl Internal subroutine of AC_PATH_X.
dnl Set ac_x_includes, ac_x_libraries, and no_x (initially yes).
AC_DEFUN(AC_PATH_X_DIRECT,
[test -z "$x_direct_test_library" && x_direct_test_library=Xt
test -z "$x_direct_test_function" && x_direct_test_function=XtMalloc
test -z "$x_direct_test_include" && x_direct_test_include=X11/Intrinsic.h
AC_TRY_CPP([#include <$x_direct_test_include>],
[no_x= ac_x_includes=],
[  for ac_dir in               \
    /usr/X11R6/include        \
    /usr/X11R5/include        \
    /usr/X11R4/include        \
                              \
    /usr/include/X11R6        \
    /usr/include/X11R5        \
    /usr/include/X11R4        \
                              \
    /usr/local/X11R6/include  \
    /usr/local/X11R5/include  \
    /usr/local/X11R4/include  \
                              \
    /usr/local/include/X11R6  \
    /usr/local/include/X11R5  \
    /usr/local/include/X11R4  \
                              \
    /usr/X11/include          \
    /usr/include/X11          \
    /usr/local/X11/include    \
    /usr/local/include/X11    \
                              \
    /usr/X386/include         \
    /usr/x386/include         \
    /usr/XFree86/include/X11  \
                              \
    /usr/include              \
    /usr/local/include        \
    /usr/unsupported/include  \
    /usr/athena/include       \
    /usr/local/x11r5/include  \
    /usr/lpp/Xamples/include  \
                              \
    /usr/openwin/include      \
    /usr/openwin/share/include \
    ; \
  do
    if test -r "$ac_dir/$x_direct_test_include"; then
      no_x= ac_x_includes=$ac_dir
      break
    fi
  done])

# Check for the libraries.
# See if we find them without any special options.
# Don't add to $LIBS permanently.
ac_save_LIBS="$LIBS"
LIBS="$LIBS -l$x_direct_test_library"
AC_TRY_LINK(, [${x_direct_test_function}()],
[LIBS="$ac_save_LIBS" no_x= ac_x_libraries=],
[LIBS="$ac_save_LIBS"
# First see if replacing the include by lib works.
for ac_dir in `echo "$ac_x_includes" | sed s/include/lib/` \
    /usr/X11R6/lib        \
    /usr/X11R5/lib        \
    /usr/X11R4/lib        \
                          \
    /usr/lib/X11R6        \
    /usr/lib/X11R5        \
    /usr/lib/X11R4        \
                          \
    /usr/local/X11R6/lib  \
    /usr/local/X11R5/lib  \
    /usr/local/X11R4/lib  \
                          \
    /usr/local/lib/X11R6  \
    /usr/local/lib/X11R5  \
    /usr/local/lib/X11R4  \
                          \
    /usr/X11/lib          \
    /usr/lib/X11          \
    /usr/local/X11/lib    \
    /usr/local/lib/X11    \
                          \
    /usr/X386/lib         \
    /usr/x386/lib         \
    /usr/XFree86/lib/X11  \
                          \
    /usr/lib              \
    /usr/local/lib        \
    /usr/unsupported/lib  \
    /usr/athena/lib       \
    /usr/local/x11r5/lib  \
    /usr/lpp/Xamples/lib  \
                          \
    /usr/openwin/lib      \
    /usr/openwin/share/lib \
    ; \
do
  for ac_extension in a so sl; do
    if test -r $ac_dir/lib${x_direct_test_library}.$ac_extension; then
      no_x= ac_x_libraries=$ac_dir
      break 2
    fi
  done
done])])

dnl Find additional X libraries, magic flags, etc.
AC_DEFUN(AC_PATH_XTRA,
[AC_REQUIRE([AC_ISC_POSIX])dnl
AC_REQUIRE([AC_PATH_X])dnl
if test "$no_x" = yes; then 
  # Not all programs may use this symbol, but it does not hurt to define it.
  X_CFLAGS="$X_CFLAGS -DX_DISPLAY_MISSING"
else
  if test -n "$x_includes"; then
    X_CFLAGS="$X_CFLAGS -I$x_includes"
  fi

  # It would be nice to have a more robust check for the -R ld option than
  # just checking for Solaris.
  # It would also be nice to do this for all -L options, not just this one.
  if test -n "$x_libraries"; then
    X_LIBS="$X_LIBS -L$x_libraries"
    if test "`(uname) 2>/dev/null`" = SunOS &&
      uname -r | grep '^5' >/dev/null; then
      X_LIBS="$X_LIBS -R$x_libraries"
    fi
  fi

  # Check for libraries that X11R6 Xt/Xaw programs need.

  ac_save_LDFLAGS="$LDFLAGS"
  LDFLAGS="$LDFLAGS -L$x_libraries"
  # SM needs ICE to (dynamically) link under SunOS 4.x (so we have to
  # check for ICE first), but we must link in the order -lSM -lICE or
  # we get undefined symbols.  So assume we have SM if we have ICE.
  # These have to be linked with before -lX11, unlike the other
  # libraries we check for below, so use a different variable.
  #  --interran@uluru.Stanford.EDU, kb@cs.umb.edu.
  AC_CHECK_LIB(ICE, IceConnectionNumbers,
    [X_PRE_LIBS="$X_PRE_LIBS -lSM -lICE"])
  LDFLAGS="$ac_save_LDFLAGS"

  # Check for system-dependent libraries X programs must link with.

  if test "$ISC" = yes; then
    X_EXTRA_LIBS="$X_EXTRA_LIBS -lnsl_s -linet"
  else
    # Martyn.Johnson@cl.cam.ac.uk says this is needed for Ultrix, if the X
    # libraries were built with DECnet support.  And karl@cs.umb.edu says
    # the Alpha needs dnet_stub (dnet does not exist).
    AC_CHECK_LIB(dnet, dnet_ntoa, [X_EXTRA_LIBS="$X_EXTRA_LIBS -ldnet"])
    if test $ac_cv_lib_dnet = no; then
      AC_CHECK_LIB(dnet_stub, dnet_ntoa,
        [X_EXTRA_LIBS="$X_EXTRA_LIBS -ldnet_stub"])
    fi

    # msh@cis.ufl.edu says -lnsl (and -lsocket) are needed for his 386/AT,
    # to get the SysV transport functions.
    # Not sure which flavor of 386 UNIX this is, but it seems harmless to
    # check for it.
    AC_CHECK_LIB(nsl, t_accept, [X_EXTRA_LIBS="$X_EXTRA_LIBS -lnsl"])

    # lieder@skyler.mavd.honeywell.com says without -lsocket,
    # socket/setsockopt and other routines are undefined under SCO ODT 2.0.
    # But -lsocket is broken on IRIX, according to simon@lia.di.epfl.ch.
    if test "`(uname) 2>/dev/null`" != IRIX; then
      AC_CHECK_LIB(socket, socket, [X_EXTRA_LIBS="$X_EXTRA_LIBS -lsocket"])
    fi
  fi
fi
AC_SUBST(X_CFLAGS)dnl
AC_SUBST(X_PRE_LIBS)dnl
AC_SUBST(X_LIBS)dnl
AC_SUBST(X_EXTRA_LIBS)dnl
])


dnl ### Checks for UNIX variants
dnl These are kludges which should be replaced by a single POSIX check.


AC_DEFUN(AC_AIX,
[AC_BEFORE([$0], [AC_TRY_COMPILE])dnl
AC_BEFORE([$0], [AC_TRY_LINK])dnl
AC_BEFORE([$0], [AC_TRY_RUN])dnl
AC_MSG_CHECKING(for AIX)
AC_EGREP_CPP(yes,
[#ifdef _AIX
  yes
#endif
], [AC_MSG_RESULT(yes); AC_DEFINE(_ALL_SOURCE)], AC_MSG_RESULT(no))
])

AC_DEFUN(AC_MINIX,
[AC_BEFORE([$0], [AC_TRY_COMPILE])dnl
AC_BEFORE([$0], [AC_TRY_LINK])dnl
AC_BEFORE([$0], [AC_TRY_RUN])dnl
AC_CHECK_HEADER(minix/config.h, MINIX=yes, MINIX=)
if test "$MINIX" = yes; then
  AC_DEFINE(_POSIX_SOURCE)
  AC_DEFINE(_POSIX_1_SOURCE, 2)
  AC_DEFINE(_MINIX)
fi
])

AC_DEFUN(AC_ISC_POSIX,
[AC_BEFORE([$0], [AC_TRY_LINK])dnl
AC_BEFORE([$0], [AC_TRY_LINK])dnl
AC_BEFORE([$0], [AC_TRY_RUN])dnl
AC_MSG_CHECKING(for POSIXized ISC)
if test -d /etc/conf/kconfig.d &&
  grep _POSIX_VERSION [/usr/include/sys/unistd.h] >/dev/null 2>&1
then
  AC_MSG_RESULT(yes)
  ISC=yes # If later tests want to check for ISC.
  AC_DEFINE(_POSIX_SOURCE)
  if test "$GCC" = yes; then
    CC="$CC -posix"
  else
    CC="$CC -Xp"
  fi
else
  AC_MSG_RESULT(no)
  ISC=
fi
])

AC_DEFUN(AC_XENIX_DIR,
[AC_OBSOLETE([$0], [; instead use AC_HEADER_DIRENT])dnl
AC_REQUIRE([AC_DIR_HEADER])dnl
AC_MSG_CHECKING(for Xenix)
AC_EGREP_CPP(yes,
[#if defined(M_XENIX) && !defined(M_UNIX)
  yes
#endif
], [AC_MSG_RESULT(yes); XENIX=yes], [AC_MSG_RESULT(no); XENIX=])
if test "$XENIX" = yes; then
  # Make sure -ldir precedes -lx.
  test $ac_header_dirent = dirent.h && LIBS="$LIBS -ldir"
  LIBS="$LIBS -lx"
fi
])

AC_DEFUN(AC_DYNIX_SEQ,
[AC_OBSOLETE([$0], [; instead use AC_FUNC_GETMNTENT])dnl
AC_CHECK_LIB(seq, getmntent, LIBS="$LIBS -lseq")
])

AC_DEFUN(AC_IRIX_SUN,
[AC_OBSOLETE([$0], [; instead use AC_FUNC_GETMNTENT or AC_CHECK_LIB(sun, getpwnam)])dnl
AC_CHECK_LIB(sun, getmntent, LIBS="$LIBS -lsun")
])

AC_DEFUN(AC_SCO_INTL,
[AC_OBSOLETE([$0], [; instead use AC_FUNC_STRFTIME])dnl
AC_CHECK_LIB(intl, strftime, LIBS="$LIBS -lintl")
])

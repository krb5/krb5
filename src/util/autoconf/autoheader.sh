#!/bin/sh
# autoheader -- create `config.h.in' from `configure.in'
# Copyright (C) 1992, 1993, 1994 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

# Written by Roland McGrath.

# If given no args, create `config.h.in' from template file `configure.in'.
# With one arg, create a header file on standard output from
# the given template file.

usage="Usage: autoheader [-h] [--help] [-m dir] [--macrodir=dir] 
                  [-v] [--version] [template-file]" 

# NLS nuisances.
# These must not be set unconditionally because not all systems understand
# e.g. LANG=C (notably SCO).
if test "${LC_ALL+set}" = 'set' ; then LC_ALL=C; export LC_ALL; fi
if test "${LANG+set}"   = 'set' ; then LANG=C;   export LANG;   fi

test -z "${AC_MACRODIR}" && AC_MACRODIR=@datadir@
test -z "${M4}" && M4=@M4@
case "${M4}" in
/*) # Handle the case that m4 has moved since we were configured.
    # It may have been found originally in a build directory.
    test -f "${M4}" || M4=m4 ;;
esac

print_version=""
while test $# -gt 0 ; do
   case "z${1}" in 
      z-h | z--help | z--h* )
         echo "${usage}"; exit 0 ;;
      z--macrodir=* | z--m*=* )
         AC_MACRODIR="`echo \"${1}\" | sed -e 's/^[^=]*=//'`"
         shift ;;
      z-m | z--macrodir | z--m* ) 
         shift
         test $# -eq 0 && { echo "${usage}" 1>&2; exit 1; }
         AC_MACRODIR="${1}"
         shift ;;
      z-v | z--version | z--v* )
         print_version="-DAC_PRINT_VERSION"
         shift ;;
      z-- )     # Stop option processing
        shift; break ;;
      z- )	# Use stdin as input.
        break ;;
      z-* )
        echo "${usage}" 1>&2; exit 1 ;;
      * )
        break ;;
   esac
done

TEMPLATES="${AC_MACRODIR}/acconfig.h"
test -r acconfig.h && TEMPLATES="${TEMPLATES} acconfig.h"
MACROFILES="${AC_MACRODIR}/acgeneral.m4 ${AC_MACRODIR}/acspecific.m4"
test -r ${AC_MACRODIR}/aclocal.m4 \
   && MACROFILES="${MACROFILES} ${AC_MACRODIR}/aclocal.m4"
test -r aclocal.m4 && MACROFILES="${MACROFILES} aclocal.m4"
MACROFILES="${print_version} ${MACROFILES}"

case $# in
  0) if test -n "$print_version"
       then infile=/dev/null
       else infile=configure.in; fi ;;
  1) infile=$1 ;;
  *) echo "$usage" >&2; exit 1 ;;
esac

# These are the alternate definitions of the acgeneral.m4 macros we want to
# redefine.  They produce strings in the output marked with "@@@" so we can
# easily extract the information we want.  The `#' at the end of the first
# line of each definition seems to be necessary to prevent m4 from eating
# the newline, which makes the @@@ not always be at the beginning of a line.
frob='define([AC_DEFINE],[#
@@@syms="$syms $1"@@@
])dnl
define([AC_SIZEOF_TYPE],[#
@@@types="$types,$1"@@@
])dnl
define([AC_HAVE_FUNCS],[#
@@@funcs="$funcs $1"@@@
])dnl
define([AC_HAVE_HEADERS],[#
@@@headers="$headers $1"@@@
])dnl
define([AC_CONFIG_HEADER],[#
@@@config_h=$1@@@
])dnl
define([AC_HAVE_LIBRARY], [#
changequote(/,/)dnl
define(/libname/, dnl
patsubst(patsubst($1, /lib\([^\.]*\)\.a/, /\1/), /-l/, //))dnl
changequote([,])dnl
@@@libs="$libs libname"@@@
# If it was found, we do:
$2
# If it was not found, we do:
$3
])dnl
'

config_h=config.h
syms=
types=
funcs=
headers=
libs=

# We extract assignments of SYMS, TYPES, FUNCS, HEADERS, and LIBS from the
# modified autoconf processing of the input file.  The sed hair is
# necessary to win for multi-line macro invocations.
eval "`echo \"$frob\" \
       | $M4 $MACROFILES - $infile \
       | sed -n -e '
		: again
		/^@@@.*@@@$/s/^@@@\(.*\)@@@$/\1/p
		/^@@@/{
			s/^@@@//p
			n
			s/^/@@@/
			b again
		}'`"

test -n "$print_version" && exit 0

# Make SYMS newline-separated rather than blank-separated, and remove dups.
syms="`for sym in $syms; do echo $sym; done | sort | uniq`"

if test $# -eq 0; then
  tmpout=autoh$$
  trap "rm -f $tmpout; exit 1" 1 2 15
  exec > $tmpout
fi

# Don't write "do not edit" -- it will get copied into the
# config.h, which it's ok to edit.
echo "/* ${config_h}.in.  Generated automatically from $infile by autoheader.  */"

test -f ${config_h}.top && cat ${config_h}.top

# This puts each paragraph on its own line, separated by @s.
if test -n "$syms"; then
   # Make sure the boundary of template files is also the boundary
   # of the paragraph.  Extra newlines don't hurt since they will
   # be removed.
   for t in $TEMPLATES; do cat $t; echo; echo; done |
   # The sed script is suboptimal because it has to take care of
   # some broken seds (e.g. AIX) that remove '\n' from the
   # pattern/hold space if the line is empty. (junio@twinsun.com).
   sed -n -e '
	/^[ 	]*$/{
		x
		s/\n/@/g
		p
		s/.*/@/
		x
	}
	H' | sed -e 's/@@*/@/g' |
   # Select each paragraph that refers to a symbol we picked out above.
   fgrep "$syms" |
   tr @ \\012
fi

echo "$types" | tr , \\012 | sort | uniq | while read ctype; do
  test -z "$ctype" && continue
  # Solaris 2.3 tr rejects noncontiguous characters in character classes.
  sym="`echo "${ctype}" | tr '[a-z] *' '[A-Z]_P'`"
  echo "
/* The number of bytes in a ${ctype}.  */
#undef SIZEOF_${sym}"
done

for func in `for x in $funcs; do echo $x; done | sort | uniq`; do
  sym="`echo ${func} | sed 's/[^a-zA-Z0-9_]/_/g' | tr '[a-z]' '[A-Z]'`"
  echo "
/* Define if you have ${func}.  */
#undef HAVE_${sym}"
done

for header in `for x in $headers; do echo $x; done | sort | uniq`; do
  sym="`echo ${header} | sed 's/[^a-zA-Z0-9_]/_/g' | tr '[a-z]' '[A-Z]'`"
  echo "
/* Define if you have the <${header}> header file.  */
#undef HAVE_${sym}"
done

for lib in `for x in $libs; do echo $x; done | sort | uniq`; do
  sym="`echo ${lib} | sed 's/[^a-zA-Z0-9_]/_/g' | tr '[a-z]' '[A-Z]'`"
  echo "
/* Define if you have the ${lib} library (-l${lib}).  */
#undef HAVE_LIB${sym}"
done

test -f ${config_h}.bot && cat ${config_h}.bot

status=0

for sym in $syms; do
  if fgrep $sym $TEMPLATES >/dev/null; then
    : # All is well.
  else
    echo "$0: Symbol \`${sym}' is not covered by $TEMPLATES" >&2
    status=1
  fi
done

if test $# -eq 0; then
  if test $status -eq 0; then
    if cmp -s $tmpout ${config_h}.in; then
      rm -f $tmpout
    else
      mv -f $tmpout ${config_h}.in
    fi
  else
    rm -f $tmpout
  fi
fi

exit $status

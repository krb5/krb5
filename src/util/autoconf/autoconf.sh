#!/bin/sh
# autoconf -- create `configure' using m4 macros
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

# If given no args, create `configure' from template file `configure.in'.
# With one arg, create a configure script on standard output from
# the given template file.

usage="Usage: autoconf [-h] [--help] [-m dir] [--macrodir=dir] 
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

tmpout=/tmp/acout.$$

print_version=
while test $# -gt 0 ; do
   case "z${1}" in 
      z-h | z--help | z--h* )
         echo "${usage}" 1>&2; exit 0 ;;
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
         infile=/dev/null tmpout=/dev/null
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

if test -z "$print_version"; then
  case $# in
    0) infile=configure.in ;;
    1) infile="$1" ;;
    *) echo "$usage" >&2; exit 1 ;;
  esac

  trap 'rm -f $tmpin $tmpout; exit 1' 1 2 15

  if test z$infile = z-; then
    tmpin=/tmp/acin.$$
    infile=$tmpin
    cat > $infile
  elif test ! -s "${infile}"; then
    echo "autoconf: ${infile}: No such file or directory" >&2
    exit 1
  fi
fi

MACROFILES="${AC_MACRODIR}/acgeneral.m4 ${AC_MACRODIR}/acspecific.m4"
test -r ${AC_MACRODIR}/aclocal.m4 \
   && MACROFILES="${MACROFILES} ${AC_MACRODIR}/aclocal.m4"
test -r aclocal.m4 && MACROFILES="${MACROFILES} aclocal.m4"
MACROFILES="${print_version} ${MACROFILES}"

$M4 $MACROFILES $infile > $tmpout || { st=$?; rm -f $tmpin $tmpout; exit $st; }

test -n "$print_version" && exit 0

# You could add your own prefixes to pattern if you wanted to check for
# them too, e.g. pattern="AC_\|ILT_", except that UNIX sed doesn't do
# alternation.
pattern="AC_"

status=0
if grep "${pattern}" $tmpout > /dev/null 2>&1; then
  echo "autoconf: Undefined macros:" >&2
  grep "${pattern}" $tmpout | sed "s/.*\(${pattern}[_A-Z0-9]*\).*/\1/" |
    while read name; do
      grep -n $name $infile /dev/null
    done | sort -u >&2
  status=1
fi

case $# in
  0) cat $tmpout > configure; chmod +x configure ;;
  1) cat $tmpout ;;
esac

rm -f $tmpout
exit $status

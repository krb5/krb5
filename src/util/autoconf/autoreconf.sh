#! /bin/sh
# autoreconf - remake all Autoconf configure scripts in a directory tree
# Copyright (C) 1994 Free Software Foundation, Inc.

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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

usage="\
Usage: autoreconf [-f] [-h] [--help] [-m dir] [--macrodir=dir]
       [-l dir] [--localdir=dir] [--force] [--verbose] [--version]"

localdir=
verbose=no
show_version=no
force=no

test -z "$AC_MACRODIR" && AC_MACRODIR=@datadir@

while test $# -gt 0; do
  case "$1" in 
  -h | --help | --h*)
    echo "$usage"; exit 0 ;;
  --localdir=* | --l*=* )
    localdir="`echo \"${1}\" | sed -e 's/^[^=]*=//'`"
    shift ;;
  -l | --localdir | --l*)
    shift
    test $# -eq 0 && { echo "${usage}" 1>&2; exit 1; }
    localdir="${1}"
    shift ;;
  --macrodir=* | --m*=* )
    AC_MACRODIR="`echo \"$1\" | sed -e 's/^[^=]*=//'`"
    shift ;;
  -m | --macrodir | --m*)
    shift
    test $# -eq 0 && { echo "$usage" 1>&2; exit 1; }
    AC_MACRODIR="$1"
    shift ;;
  --verbose | --verb*)
    verbose=yes; shift ;;
  -f | --force)
    force=yes; shift ;;
  --version | --vers*)
    show_version=yes; shift ;;
  --)     # Stop option processing.
    shift; break ;;
  -*) echo "$usage" 1>&2; exit 1 ;;
  *) break ;;
  esac
done

if test $show_version = yes; then
  version=`sed -n 's/define.AC_ACVERSION.[ 	]*\([0-9.]*\).*/\1/p' \
    $AC_MACRODIR/acgeneral.m4`
  echo "Autoconf version $version"
  exit 0
fi

if test $# -ne 0; then
  echo "$usage" 1>&2; exit 1
fi

# The paths to the autoconf and autoheader scripts, at the top of the tree.
top_autoconf=`echo $0|sed s%autoreconf%autoconf%`
top_autoheader=`echo $0|sed s%autoreconf%autoheader%`

# Make a list of directories to process.
# The xargs grep filters out Cygnus configure.in files.
find . -name configure.in -print |
xargs grep -l AC_OUTPUT |
sed 's%/configure\.in$%%; s%^./%%' |
while read dir; do
  (
  cd $dir || continue

  case "$dir" in
  .) dots= ;;
  *) # A "../" for each directory in /$dir.
     dots=`echo /$dir|sed 's%/[^/]*%../%g'` ;;
  esac

  case "$0" in
  /*)  autoconf=$top_autoconf; autoheader=$top_autoheader ;;
  */*) autoconf=$dots$top_autoconf; autoheader=$dots$top_autoheader ;;
  *)   autoconf=$top_autoconf; autoheader=$top_autoheader ;;
  esac

  case "$AC_MACRODIR" in
  /*)  macrodir_opt="--macrodir=$AC_MACRODIR" ;;
  *)   macrodir_opt="--macrodir=$dots$AC_MACRODIR" ;;
  esac

  case "$localdir" in
  "")  localdir_opt=
       aclocal=aclocal.m4 ;;
  /*)  localdir_opt="--localdir=$localdir"
       aclocal=$localdir/aclocal.m4 ;;
  *)   localdir_opt="--localdir=$dots$localdir"
       aclocal=$dots$localdir/aclocal.m4 ;;
  esac

  test ! -f $aclocal && aclocal=

  if test $force = no && test -f configure &&
    ls -lt configure configure.in $aclocal | sed 1q |
      grep 'configure$' > /dev/null
  then
    :
  else
    test $verbose = yes && echo running autoconf in $dir
    $autoconf $macrodir_opt $localdir_opt
  fi

  if grep AC_CONFIG_HEADER configure.in >/dev/null; then
    template=`sed -n '/AC_CONFIG_HEADER/{
s%[^#]*AC_CONFIG_HEADER(\([^)]*\).*%\1%
t here
: here
s%.*:%%
t colon
s%$%.in%
: colon
p
q
}' configure.in`
    if test ! -f $template || grep autoheader $template >/dev/null; then
      if test $force = no && test -f $template &&
	ls -lt $template configure.in $aclocal | sed 1q |
	  grep "$template$" > /dev/null
      then
        :
      else
        test $verbose = yes && echo running autoheader in $dir
        $autoheader $macrodir_opt $localdir_opt
      fi
    fi
  fi
  )
done


#!/bin/sh
#
# libupdate: Update a library based on a file of object files.
#
# Usage: libupdate <library> <object filelist> <directory> 
#

ARADD="@ARADD@"
ARCHIVE="@ARCHIVE@"

force=
rmcmd=
arcmd="$ARADD"
if test "$1" = "--force" 
then
	force=yes
	arcmd="$ARCHIVE"
	rmcmd="rm -f $library"
	shift
fi

library=$1
oblist=$2
dir=$3

stamp=`echo $library | sed -e 's/.a$/.stamp/'`

if test "$force" != yes -a -f $stamp && \
   ls -lt $stamp $oblist | sed 1q | grep $stamp$ > /dev/null || \
   test -z "`cat $oblist`"
then
	exit 0
fi

echo "Updating library $library from $oblist"

$rmcmd
$arcmd $library `cat $oblist | \
		sed -e "s;^\([^ ]*\);$dir/\1;g" -e "s; \([^ ]*\); $dir/\1;g"`








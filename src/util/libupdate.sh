#!/bin/sh
#
# libupdate: Update a library based on a file of object files.
#
# Usage: libupdate <library> <object filelist> <directory> 
#

ARADD="@ARADD@"
ARCHIVE="@ARCHIVE@"

force=
arcmd="$ARADD"
if test "$1" = "--force" 
then
	force=yes
	arcmd="$ARCHIVE"
	shift
fi

library=$1
oblist=$2
dir=$3

if test "$force" != yes -a -f $library && \
   ls -lt $library $oblist | head -1 | grep $library$ > /dev/null || \
   test -z "`cat $oblist`"
then
	exit 0
fi

echo "Updating library $library from $oblist"

$arcmd $library `cat $oblist | \
		sed -e "s;^\([^ ]*\);$dir/\1;g" -e "s; \([^ ]*\); $dir/\1;g"`
touch $library








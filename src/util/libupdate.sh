#!/bin/sh
#
# libupdate: Update a library based on a file of object files.
#
# Usage: libupdate <library> <object filelist> <directories> 
#

ARADD="@ARADD@"
ARCHIVE="@ARCHIVE@"

case "$1" in
--force)
	force=yes
	arcmd="$ARCHIVE"
	shift
	rmcmd="rm -f $1"
	;;
*)
	arcmd="$ARADD"
	rmcmd=
	force=
esac
library=$1
oblist=$2
shift
shift
for dir do
	oblists="$oblists${oblists+ }$dir/$oblist";
done

stamp=`echo $library | sed -e 's/.a$/.stamp/'`

if test "$force" != yes -a -f $stamp && \
   ls -lt $stamp $oblists | sed 1q | grep $stamp$ > /dev/null || \
   test -z "`cat $oblists`"
then
	exit 0
fi

echo "Updating library $library from $oblists"

$rmcmd
$arcmd $library `for dir do (cd $dir; cat $oblist | \
	sed -e "s;^\([^ ]*\);$dir/\1;g" -e "s; \([^ ]*\); $dir/\1;g"); done`

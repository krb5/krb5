#!/bin/sh
#
# makeshlib: Make a shared library.....
# This script is used on platforms
# like AIX where making
# a shared library is somewhat more complex than just
# calling ld.
#
# Usage: makeshlib  <version> -o <library><objects> <otherstuff>

#

host=@HOST_TYPE@
CC="@CC@"
HAVE_GCC=@HAVE_GCC@

version=$1;shift
shift; # discard -o
library=$1; shift
for opt in $* ; do
	case $opt in
	    -*)
	    LDFLAGS="$LDFLAGS $opt"
	    ;;
	  *)
	    OBJS="$OBJS $opt"
	  ;;
	esac
done

case $host  in
*-*-aix*)
	echo rm $library 
	rm -f $library 2>/dev/null
	echo ar cq $library $OBJS
	ar cq $library $OBJS || exit $?
	dump -g $library | sed -e 's/^[ 	]*[0-9][0-9]*[ 	]*\([^ 	.][^ 	]*\)$/\1/p;d' | sort | uniq > ${library}.syms
	stat=$?
	if [ $stat -eq 0 ] ; then
	    if test "$HAVE_GCC" = "yes" ; then
		$CC -o shr.o.$version $library  -nostartfiles -Xlinker -bgcbypass:1 -Xlinker -bfilelist -Xlinker -bM:SRE -Xlinker -bE:${library}.syms -Xlinker -berok $LDFLAGS -lc
	    else
		# Pull in by explicit pathname so we don't get gnu ld if
		# installed (it could be even if we chose not to use gcc).
		# Better still would be to do this through $CC -- how do
		# we get crt0.o left out?
    echo	/bin/ld -o shr.o.$version $library -H512 -T512 -bnoentry -bM:SRE $LDFLAGS -bgcbypass:1 -bnodelcsect -bE:${library}.syms -berok $libdirfl $liblist -lc
		/bin/ld -o shr.o.$version $library -H512 -T512 -bnoentry -bM:SRE $LDFLAGS -bgcbypass:1 -bnodelcsect -bE:${library}.syms -berok -lc
	    fi
	    stat=$?
	    if [ $stat -eq 0 ] ; then
		rm $library ${library}.syms
		ar cq $library shr.o.$version
		stat=$?
		chmod +x $library
		rm shr.o.$version
	    else
		rm -f $library
	    fi
	fi
	;;

*)
	echo "Host type $host not supported!"
	exit 1
esac
exit $stat

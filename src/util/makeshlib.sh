#!/bin/sh
#
# makeshlib: Make a shared library.....
#
# Usage: makeshlib  <library> <libdirfl> <liblist> <flags>	\
#	<directories>
#

host=@HOST_TYPE@
CC="@CC@"
HAVE_GCC=@HAVE_GCC@

library=$1 ; shift
libdirfl=$1; shift
liblist=$1; shift
ldflags=$1; shift

case $host in
*-*-solaris*)
	FILES=`for i 
	do
		sed -e "s;^;$i/shared/;" -e "s; ; $i/shared/;g" $i/DONE
	done`
 
	echo $CC -G $ldflags -o $library $FILES $libdirfl $liblist
	$CC -G $ldflags -o $library $FILES $libdirfl $liblist
	stat=$?
	;;
*-*-aix*)
	FILES=`for i 
	do
		sed -e "s;^;$i/;" -e "s; ; $i/;g" $i/DONE
	done`
echo rm $library 
rm -f $library 2>/dev/null
ar cq $library $FILES || exit $?
	dump -g $library | sed -e 's/^[ 	]*[0-9][0-9]*[ 	]*\([^ 	.][^ 	]*\)$/\1/p;d' | sort | uniq > ${library}.syms
	stat=$?
	if [ $stat -eq 0 ]
	then
	if test $HAVE_GCC = "yes" ; then
		$CC -o shr.o $library -nostartfiles -Xlinker -bgcbypass:1 -Xlinker -bfilelist -Xlinker -bM:SRE -Xlinker -bE:${library}.syms $ldflags $liblist $libdirfl
		else ld -o shr.o $library -H512 -T512 -bM:SRE -lc $ldflags -bfilelist -bgcbypass:1 -bnodelcsect -x -bE:${library}.syms $libdirfl $liblist
            fi
 stat=$?
	if [ $stat -eq 0 ]
	      then
	      rm $library ${library}.syms
	      ar cq $library shr.o
	      stat=$?
	      rm shr.o
	     else
	     rm -f $library
fi
	   fi
;;
alpha-*-osf*)
	FILES=`for i 
	do
		sed -e "s;^;$i/;" -e "s; ; $i/;g" $i/DONE

	done`

	echo 	ld -shared -error_unresolved $ldflags -o $library -all $FILES $libdirfl $liblist -none -lc -update_registry ../../so_locations
	ld -shared -error_unresolved $ldflags -o $library -all $FILES $libdirfl $liblist -none -lc -update_registry ../../so_locations
	stat=$?
	;;

*)
	echo "Host type $host not supported!"
	exit 1
esac
exit $stat


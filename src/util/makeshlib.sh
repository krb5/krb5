#!/bin/sh
#
# makeshlib: Make a shared library.....
#
# Usage: makeshlib  <library> <libdirfl> <liblist> <flags>	\
#	<library version> <directories>
#

host=@HOST_TYPE@
CC="@CC@"
HAVE_GCC=@HAVE_GCC@

library=$1 ; shift
libdirfl=$1; shift
liblist=$1; shift
ldflags=$1; shift
VERSION="$1" ; shift

case $host  in
*-*-netbsd*)
	FILES=`for i
	do
		sed -e "s;^;$i/shared/;" -e "s; ; $i/shared/;g" -e "s;^$i/shared/\$;;" $i/DONE
	done`
	# Hack to deal with the fact that with cc options are different
	# from ld...
	ldflags=`echo $ldflags |sed  -e "s/-Wl,//g"`
	echo ld -Bshareable $ldflags -o $library $FILES $libdirfl $liblist
	ld -Bshareable $ldflags -o $library $FILES $libdirfl $liblist
	stat=$?
	;;
*-*-hpux*)
	FILES=`for i
	do
		sed -e "s;^;$i/shared/;" -e "s; ; $i/shared/;g" $i/DONE
	done`
	ldflags="`echo $ldflags | sed 's/-Wl,+b,/+b /g'`"
	echo ld -b $ldflags -o $library $FILES $libdirfl $liblist
	ld -b $ldflags -o $library $FILES $libdirfl $liblist
	stat=$?
	;;
*-*-linux*)
	FILES=`for i 
	do
		sed -e "s;^;$i/shared/;" -e "s; ; $i/shared/;g" $i/DONE
	done`
 
	echo $CC -G $ldflags -o $library $optflags $FILES $libdirfl $liblist 
	$CC --shared $ldflags -o $library $FILES $libdirfl $liblist
	stat=$?
	;;
mips-sni-sysv4)
	FILES=`for i 
	do
		sed -e "s;^;$i/shared/;" -e "s; ; $i/shared/;g" $i/DONE
	done`
 
	optflags=""
	if test "$HAVE_GCC"x = "x" ; then
		optflags="-h $library"
	fi
	ldflags="`echo $ldflags | sed -e 's/-R /-R/g'`"

	echo $CC -G $ldflags -o $library $optflags $FILES $libdirfl $liblist 
	$CC -G $ldflags -o $library $optflags $FILES $libdirfl $liblist
	stat=$?
	;;
*-*-solaris*)
	FILES=`for i 
	do
		sed -e "s;^;$i/shared/;" -e "s; ; $i/shared/;g" $i/DONE
	done`
 
	optflags=""
	if test "$HAVE_GCC"x = "x" ; then
		optflags="-h $library"
	fi

	echo $CC -G $ldflags -o $library $optflags $FILES $libdirfl $liblist 
	$CC -G $ldflags -o $library $optflags $FILES $libdirfl $liblist
	stat=$?
	;;
*-*-sunos*)
	FILES=`for i 
	do
		sed -e "s;^;$i/shared/;" -e "s; ; $i/shared/;g" $i/DONE
	done`
 
	optflags=""
	if test "$HAVE_GCC"x = "x" ; then
		optflags="-h $library"
	fi

	echo ld -dp -assert pure-text $ldflags -o $library $optflags $FILES $libdirfl
	ld -dp -assert pure-text $ldflags -o $library $optflags $FILES $libdirfl
	stat=$?
	;;
*-*-aix*)
	FILES=`for i 
	do
		sed -e "s;^;$i/;" -e "s; ; $i/;g" $i/DONE
	done`
	echo rm $library 
	rm -f $library 2>/dev/null
	echo ar cq $library $FILES
	ar cq $library $FILES || exit $?
	dump -g $library | sed -e 's/^[ 	]*[0-9][0-9]*[ 	]*\([^ 	.][^ 	]*\)$/\1/p;d' | sort | uniq > ${library}.syms
	stat=$?
	if [ $stat -eq 0 ] ; then
	    if test "$HAVE_GCC" = "yes-broken" ; then
		# yikes!  this part won't handle gnu ld either!
		# disable it for now.
		$CC -o shr.o.$VERSION $library -nostartfiles -Xlinker -bgcbypass:1 -Xlinker -bfilelist -Xlinker -bM:SRE -Xlinker -bE:${library}.syms $ldflags $liblist $libdirfl
	    else
		# Pull in by explicit pathname so we don't get gnu ld if
		# installed (it could be even if we chose not to use gcc).
		# Better still would be to do this through $CC -- how do
		# we get crt0.o left out?
    echo	/bin/ld -o shr.o.$VERSION $library -H512 -T512 -bM:SRE $ldflags -bgcbypass:1 -bnodelcsect -bE:${library}.syms $libdirfl $liblist -lc
		/bin/ld -o shr.o.$VERSION $library -H512 -T512 -bM:SRE $ldflags -bgcbypass:1 -bnodelcsect -bE:${library}.syms $libdirfl $liblist -lc
	    fi
	    stat=$?
	    if [ $stat -eq 0 ] ; then
		rm $library ${library}.syms
		ar cq $library shr.o.$VERSION
		stat=$?
		rm shr.o.$VERSION
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

	# The "-expect_unresolved *" argument hides the fact that we don't
	# provide the (static) db library when building the (dynamic) kadm5
	# libraries.
	echo ld -shared -expect_unresolved \* $ldflags -o $library -all $FILES $libdirfl $liblist -none -lc -update_registry ../../so_locations
	ld -shared -expect_unresolved \* $ldflags -o $library -all $FILES $libdirfl $liblist -none -lc -update_registry ../../so_locations
	stat=$?
	;;

*)
	echo "Host type $host not supported!"
	exit 1
esac
exit $stat


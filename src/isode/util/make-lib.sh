: run this script through /bin/sh

M=BSD42 L= O= S= Q= SHD= MAJ= MIN= LD=ld

while [ $# -gt 0 ]
do
    A="$1"
    case $A in
	-bsd42|-mips)
		M=BSD42
		;;

	-linux) M=LINUX
		;;

	-shared)SHD=T
		;;

	-sys5)	M=SYS5
		;;

	-sys5r4) 
		M=SYS54
		;;

	-aix)	M=AIX
		;;

	-ros)	M=ROS
		;;

	-ranlib)
		case $M in
		    BSD42|ROS|LINUX)
			    echo ranlib "$L"
			    case "$L" in
				/*)	(cd /usr/tmp; ranlib "$L")
					;;

				*)	ranlib "$L"
					;;
			    esac
			    ;;

		    SYS5|AIX|old|SYS54)
			    ;;

		    *)	    echo "make-lib: mode botch" 1>&2
			    exit 1
			    ;;
		esac
		exit 0
		;;

	-quick)	Q=T
		;;

	-major) MAJ="$2"
		shift
		;;
	-minor) MIN="$2"
		shift
		;;

	-ld)	LD="$2"
		shift
		;;

	-*)	S="$S`echo $A | sed -e s%-%%`"
		;;

	*)	if [ "x$L" = x ]; then
		    L="$A"
		else
		    O="$O $A"
		fi
		;;
    esac
    shift
done

case $M in
    BSD42|ROS|LINUX)
	    if [ "x$SHD" = xT ]; then
		if [ "$M" = ROS ]; then
		    echo "Can't build shared libraries for ROS" 1>&2
		    exit 1
		fi
		if [ "$M" = Linux ]; then
		    echo "Can't build shared libraries for Linux (yet)" 1>&2
		    exit 1
		fi
		if [ "x$MAJ" = x -o "x$MIN" = x ]; then
			echo "Missing major or minor number for library" 1>&2
			exit 1
		fi
		rm -rf tmp-shared
		mkdir tmp-shared
		case "$L" in
			/*) LP="$L";;
			*) LP="../$L";;
		esac
		(cd tmp-shared; ar x "$LP"
		LSO="`echo $LP | sed 's%.a$%%'`".so.$MAJ.$MIN
		echo $LD -o "$LSO" -assert pure-text *.o
		$LD -o "$LSO" -assert pure-text *.o
		)
		rm -rf tmp-shared
	    else
		echo ar q"$S" "$L" $O
		ar q"$S" "$L" $O
		if [ "x$Q" != xT ]; then
		    echo ranlib "$L"
		    ranlib "$L"
		fi
	    fi
	    ;;

    SYS5)   if [ "x$SHD" = xT ]; then
		echo "Can't build shared libraries for Sys 5 (yet)" 1>&2
		exit 1
	    fi
	    echo ar ql"$S" "$L" $O
	    ar ql"$S" "$L" $O
	    ;;

    SYS54)  if [ "x$SHD" = xT ]; then
                rm -rf tmp-shared
                mkdir tmp-shared
                case "$L" in
                        /*) LP="$L";;
                        *) LP="../$L";;
                esac
                (cd tmp-shared; ar x "$LP"
                LSO="`echo $LP | sed 's%.a$%%'`".so
                echo $LD -o "$LSO" -G *.o
                $LD -o "$LSO" -G *.o
                )
                rm -rf tmp-shared
	    else
		echo ar q"$S" "$L" $O
		ar q"$S" "$L" $O
	    fi
            ;;


    AIX)    if [ "x$SHD" = xT ]; then
		
		exit 1
	    fi
	    echo ar rlv"$S" "$L" \`lorder $O \| tsort\`
	    ar rlv"$S" "$L" `lorder $O | tsort`
	    ;;

    old)    if [ "x$SHD" = xT ]; then
		echo "Can't build shared libraries for old style" 1>&2
		exit 1
	    fi
	    echo ar r"$S" "$L" \`lorder $O \| tsort\`
	    ar r"$S" "$L" `lorder $O | tsort`
	    ;;

    *)	    echo "make-lib: mode botch" 1>&2
	    exit 1
	    ;;
esac

exit 0

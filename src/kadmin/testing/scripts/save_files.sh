#!/bin/sh

while [ $# -gt 0 ] ; do
	case $1 in
		-start_servers)
			start_servers=$1
			;;
	esac
	shift
done

# files="/etc/inetd.conf /etc/syslog.conf /etc/krb.conf \
# 	/etc/krb.realms /etc/passwd /etc/services /etc/v5srvtab \
# 	/etc/rc.local /etc/shadow /etc/security/passwd /.k5login \
# 	/.secure/etc/passwd /etc/athena/inetd.conf"

files="/etc/krb.conf /etc/krb.realms /etc/athena/krb.conf \
	/etc/athena/krb.realms /etc/v5srvtab /etc/krb5.keytab"

name=`basename $0`

make_dne_name()
{
	dne_name="/tmp/"`echo $1 | sed -e 's,/,#,g'`".did-not-exist"
}
	
for f in $files ; do
	if [ "$name" = "save_files.sh" ]; then
		if [ -f $f.pre-secure ]; then 
			if $VERBOSE; then
			     echo "Warning!  $f.pre-secure exists, not saving."
			fi
		elif [ ! -f $f ]; then
			make_dne_name $f
			cp /dev/null $dne_name
		else
			cp $f $f.pre-secure
		fi
	else
		make_dne_name $f
		if [ -f $dne_name ]; then
			rm -f $f $dne_name
		elif [ ! -f $f.pre-secure ]; then
			if [ "x$start_servers" = "x" ]; then
			  echo "Warning!  $f.pre-secure does not exist!" 1>&2
			fi
		else
			if cp $f.pre-secure $f; then
				rm $f.pre-secure
			else
				echo "Warning! cp failed!" 1>&2
			fi
		fi
	fi
done

# DUMMY=${INETD:=/etc/inetd}
# if $VERBOSE; then
# 	echo "Killing and restarting $INETD"
# fi
# kill `$PS_ALL | awk '/inetd/ && !/awk/ {print $2}'`
# $INETD

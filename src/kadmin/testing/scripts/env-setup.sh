#!/bin/sh
#
# The KADM5 unit tests were developed to work under gmake.  As a
# result, they expect to inherit a number of environment variables.
# Rather than rewrite the tests, we simply use this script as an
# execution wrapper that sets all the necessary environment variables
# before running the program specified on its command line.
#
# The variable settings all came from OV's config.mk.
#
# Usage: env-setup.sh <command line>
#

if [ "$TOP" = "" ]; then
	echo "Error! \$TOP is not set."
	exit 1
fi

if [ "$K5ROOT" = "" ]; then
	# XXX this should default to --prefix, no?
	K5ROOT="/krb5"; export K5ROOT
fi

TESTDIR=$TOP/testing; export TESTDIR
COMPARE_DUMP=$TESTDIR/scripts/compare_dump.pl; export COMPARE_DUMP
FIX_CONF_FILES=$TESTDIR/scripts/fixup-conf-files.pl
export FIX_CONF_FILES
INITDB=$TESTDIR/scripts/init_db; export INITDB
MAKE_KEYTAB=$TESTDIR/scripts/make-host-keytab.pl; export MAKE_KEYTAB
LOCAL_MAKE_KEYTAB=$TESTDIR/scripts/make-host-keytab.pl
export LOCAL_MAKE_KEYTAB
RESTORE_FILES=$TESTDIR/scripts/restore_files.sh; export RESTORE_FILES
SAVE_FILES=$TESTDIR/scripts/save_files.sh; export SAVE_FILES
SIMPLE_DUMP=$TESTDIR/scripts/simple_dump.pl; export SIMPLE_DUMP
TCLUTIL=$TESTDIR/tcl/util.t; export TCLUTIL
BSDDB_DUMP=$TESTDIR/util/bsddb_dump; export BSDDB_DUMP
CLNTTCL=$TESTDIR/util/ovsec_kadm_clnt_tcl; export CLNTTCL
SRVTCL=$TESTDIR/util/ovsec_kadm_srv_tcl; export SRVTCL
QUALNAME=$TOP/inst-scripts/qualname.pl; export QUALNAME

START_SERVERS=$TESTDIR/scripts/start_servers $TEST_SERVER
export START_SERVERS
START_SERVERS_LOCAL=$TESTDIR/scripts/start_servers_local
export START_SERVERS_LOCAL

STOP_SERVERS=$TESTDIR/scripts/stop_servers $TEST_SERVER
export STOP_SERVERS
STOP_SERVERS_LOCAL=$TESTDIR/scripts/stop_servers_local
export STOP_SERVERS_LOCAL

KRB5_CONFIG=$K5ROOT/krb5.conf; export KRB5_CONFIG
KRB5_KDC_PROFILE=$K5ROOT/kdc.conf; export KRB5_KDC_PROFILE
KRB5_KTNAME=$K5ROOT/ovsec_adm.srvtab; export KRB5_KTNAME

if [ "$TEST_SERVER" != "" ]; then
	MAKE_KEYTAB="$MAKE_KEYTAB -server $TEST_SERVER"
fi
if [ "$TEST_PATH" != "" ]; then
	MAKE_KEYTAB="$MAKE_KEYTAB -top $TEST_PATH"
	START_SERVERS="$START_SERVERS $TEST_PATH"
	STOP_SERVERS="$STOP_SERVERS $TEST_PATH"
fi

if [ "x$PS_ALL" = "x" ]; then
	ps -axwwu >/dev/null 2>&1
	ps_bsd=$?

	ps -ef >/dev/null 2>&1
	ps_sysv=$?

	if [ $ps_bsd = 0 -a $ps_sysv = 1 ]; then
		PS_ALL="ps -auxww"
		PS_PID="ps -auxww"
	elif [ $ps_bsd = 1 -a $ps_sysv = 0 ]; then
		PS_ALL="ps -ef"
		PS_PID="ps -fp"
	else
		PS_ALL="ps -auxww"
		PS_PID="ps -auxww"
		echo "WARNING!  Cannot auto-detect ps type, assuming BSD."
	fi

	export PS_ALL PS_PID
fi

exec ${1+"$@"}

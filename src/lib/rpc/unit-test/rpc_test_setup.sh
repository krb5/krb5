#!/bin/sh
#
# This script performs additional setup for the RPC unit test.  It
# assumes that gmake has put TOP and RPC_TEST_SRVTAB into the
# environment. 
#
# $Id$
# $Source$

DUMMY=${TESTDIR=$TOP/testing}
DUMMY=${CLNTTCL=$TESTDIR/util/ovsec_kadm_clnt_tcl}
DUMMY=${TCLUTIL=$TESTDIR/tcl/util.t}; export TCLUTIL
DUMMY=${MAKE_KEYTAB=$TESTDIR/scripts/make-host-keytab.pl}

# If it's set, set it to true
if test x$VERBOSE_TEST = x; then
	VERBOSE=true
# Otherwise, set it to false
else
	VERBOSE=false
fi

if $VERBOSE; then
	REDIRECT=
else
	REDIRECT='>/dev/null'
fi

PATH=$TOP/install/admin:$PATH; export PATH

CANON_HOST=`$QUALNAME`
export CANON_HOST

cat - > /tmp/rpc_test_setup$$ <<\EOF
source $env(TCLUTIL)
set h $env(CANON_HOST)
puts stdout [ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE null $OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 server_handle]
puts stdout [ovsec_kadm_create_principal $server_handle [simple_principal server/$h] {OVSEC_KADM_PRINCIPAL} admin]
puts stdout [ovsec_kadm_randkey_principal $server_handle server/$h key]
puts stdout [ovsec_kadm_create_principal $server_handle [simple_principal notserver/$h] {OVSEC_KADM_PRINCIPAL} admin]
puts stdout [ovsec_kadm_randkey_principal $server_handle notserver/$h key]
puts stdout [ovsec_kadm_destroy $server_handle]
EOF
eval "$CLNTTCL $REDIRECT < /tmp/rpc_test_setup$$"
rm /tmp/rpc_test_setup$$

rm -f $RPC_TEST_SRVTAB

eval $MAKE_KEYTAB -princ server/$CANON_HOST $RPC_TEST_SRVTAB $REDIRECT

# grep -s "$CANON_HOST SECURE-TEST.OV.COM" /etc/krb.realms
# if [ $? != 0 ]; then
# 	eval echo \"Adding \$CANON_HOST SECURE-TEST.OV.COM to /etc/krb.realms\" $REDIRECT
# 	ed /etc/krb.realms <<EOF >/dev/null
# 1i
# $CANON_HOST SECURE-TEST.OV.COM
# .
# w
# q
# EOF
# fi

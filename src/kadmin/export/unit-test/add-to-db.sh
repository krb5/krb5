#!/bin/sh

REALM=SECURE-TEST.OV.COM; export REALM
DUMMY=${TESTDIR=$TOP/testing}; export TESTDIR
DUMMY=${SRVTCL=$TESTDIR/util/ovsec_kadm_srv_tcl}; export SRVTCL
DUMMY=${TCLUTIL=$TESTDIR/tcl/util.t}; export TCLUTIL

$SRVTCL <<'EOF'
global r

source $env(TCLUTIL)
set r $env(REALM)

proc newpol { pname } {
	puts stdout [ovsec_kadm_create_policy $server_handle [simple_policy "$pname"] {OVSEC_KADM_POLICY}]
}

proc newprinc { name } {
	global r
	puts stdout [ovsec_kadm_create_principal $server_handle [simple_principal "$name@$r"] {OVSEC_KADM_PRINCIPAL} $name]
}

proc chpass { princ pass } {
	global server_handle
	puts stdout [ovsec_kadm_chpass_principal $server_handle "$princ" "$pass"]
}

puts stdout [ovsec_kadm_init $env(SRVTCL) mrroot null $r $OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 server_handle]

puts stdout [ovsec_kadm_create_policy $server_handle "export_pwhist 0 0 0 0 10 0" {OVSEC_KADM_POLICY OVSEC_KADM_PW_HISTORY_NUM}]

### Commented out since this isn't going to work for the december beta
#newprinc "export_with space"
#newprinc "export_with\"dquote"
#newprinc "export_with\nnewline"

puts stdout [ovsec_kadm_create_principal $server_handle [princ_w_pol export_hist1@$r export_pwhist] {OVSEC_KADM_PRINCIPAL OVSEC_KADM_POLICY} hist1]

chpass export_hist1@$r hist1_a

puts stdout [ovsec_kadm_create_principal $server_handle [princ_w_pol export_hist10@$r export_pwhist] {OVSEC_KADM_PRINCIPAL OVSEC_KADM_POLICY} hist10]

chpass export_hist10@$r hist10_a
chpass export_hist10@$r hist10_b
chpass export_hist10@$r hist10_c
chpass export_hist10@$r hist10_d
chpass export_hist10@$r hist10_e
chpass export_hist10@$r hist10_f
chpass export_hist10@$r hist10_g
chpass export_hist10@$r hist10_h
chpass export_hist10@$r hist10_i

puts stdout [ovsec_kadm_destroy $server_handle]

EOF

source $env(TCLUTIL)

proc check_err {error} {
    if {! [string match {*OVSEC_KADM_UNK_PRINC*} $error]} {
	error $error
    }
}

proc delprinc {princ} {
    global server_handle

    catch {ovsec_kadm_delete_principal $server_handle $princ}
    if {[info exists errorInfo]} {
	check_err $errorInfo
    }
}
    
ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE null \
	$OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 server_handle

delprinc dne1
delprinc dne2

ovsec_kadm_destroy $server_handle

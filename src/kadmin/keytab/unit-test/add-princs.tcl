source $env(TCLUTIL)

ovsec_kadm_init admin admin $OVSEC_KADM_ADMIN_SERVICE null \
	$OVSEC_KADM_STRUCT_VERSION $OVSEC_KADM_API_VERSION_1 server_handle

ovsec_kadm_create_principal $server_handle [simple_principal kttest1] \
	{OVSEC_KADM_PRINCIPAL} kttest1

ovsec_kadm_create_principal $server_handle [simple_principal kttest2] \
	{OVSEC_KADM_PRINCIPAL} kttest2

ovsec_kadm_destroy $server_handle

#include <kadm5/admin.h>
#include <com_err.h>
#include <stdio.h>
#include <krb5.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <unistd.h>
#include <netinet/in.h>
#include <kadm5/client_internal.h>


int main(int argc, char *argv[])
{
     ovsec_kadm_ret_t ret;
     void *server_handle;
     kadm5_server_handle_t handle;
     kadm5_server_handle_rec orig_handle;
     ovsec_kadm_policy_ent_t	pol;
     ovsec_kadm_principal_ent_t	princ;
     krb5_keyblock	*key;
     krb5_principal	tprinc;
     krb5_context	context;


    krb5_init_context(&context);
     
    ret = ovsec_kadm_init("admin/none", "admin", "ovsec_adm/admin", 0,
			  OVSEC_KADM_STRUCT_VERSION, OVSEC_KADM_API_VERSION_1,
			  &server_handle);
    if(ret != OVSEC_KADM_OK) {
	com_err("test", ret, "init");
	exit(2);
    }
    handle = (kadm5_server_handle_t) server_handle;
    orig_handle = *handle;
    handle->magic_number = OVSEC_KADM_STRUCT_VERSION;
    krb5_parse_name(context, "testuser", &tprinc);
    ret = ovsec_kadm_get_principal(server_handle, tprinc, &princ);
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "get-principal",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_get_policy(server_handle, "pol1", &pol);
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "get-policy",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_create_principal(server_handle, princ, OVSEC_KADM_PRINCIPAL, "pass");
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "create-principal",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_create_policy(server_handle, pol, OVSEC_KADM_POLICY);
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "create-policy",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_modify_principal(server_handle, princ, OVSEC_KADM_PW_EXPIRATION);
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "modify-principal",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_modify_policy(server_handle, pol, OVSEC_KADM_PW_MAX_LIFE);
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "modify-policy",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_delete_principal(server_handle, tprinc);
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "delete-principal",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_delete_policy(server_handle, "pol1");
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "delete-policy",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_chpass_principal(server_handle, tprinc, "FooBar");
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "chpass",
		error_message(ret));
	exit(1);
    }
    ret = ovsec_kadm_randkey_principal(server_handle, tprinc, &key);
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "randkey",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_rename_principal(server_handle, tprinc, tprinc);
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "rename",
		error_message(ret));
	exit(1);
    }
    
    ret = ovsec_kadm_destroy(server_handle);
    if(ret != OVSEC_KADM_BAD_SERVER_HANDLE) {
	fprintf(stderr, "%s -- returned -- %s\n", "destroy",
		error_message(ret));
	exit(1);
    }

    *handle = orig_handle;
    ret = ovsec_kadm_destroy(server_handle);
    if (ret != OVSEC_KADM_OK) {
	fprintf(stderr, "valid %s -- returned -- %s\n", "destroy",
		error_message(ret));
	exit(1);
    }

    exit(0);
}

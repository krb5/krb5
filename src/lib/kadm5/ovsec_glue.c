#define USE_KADM5_API_VERSION 1
#include <kadm5/admin.h>

ovsec_kadm_ret_t ovsec_kadm_init_with_password(char *client_name, char *pass,
					       char *service_name,
					       char *realm,
					       krb5_ui_4 struct_version,
					       krb5_ui_4 api_version,
					       void **server_handle)
{
     return kadm5_init_with_password(client_name, pass, service_name,
				     realm, struct_version, api_version, 
				     server_handle);
}

ovsec_kadm_ret_t ovsec_kadm_init_with_skey(char *client_name, char *keytab,
					   char *service_name,
					   char *realm,
					   krb5_ui_4 struct_version,
					   krb5_ui_4 api_version,
					   void **server_handle)
{
     return kadm5_init_with_skey(client_name, keytab, service_name, realm,
				 struct_version, api_version,
				 server_handle);
}

ovsec_kadm_ret_t ovsec_kadm_init(char *client_name, char *from_stash,
				 char *service_name,
				 char *realm,
				 krb5_ui_4 struct_version,
				 krb5_ui_4 api_version,
				 void **server_handle)
{
     return kadm5_init(client_name, from_stash, service_name,
		       realm, struct_version, api_version,
		       server_handle);
}

ovsec_kadm_ret_t ovsec_kadm_destroy(void *server_handle)
{
     return kadm5_destroy(server_handle);
}

ovsec_kadm_ret_t ovsec_kadm_flush(void *server_handle)
{
     return kadm5_flush(server_handle);
}

ovsec_kadm_ret_t ovsec_kadm_create_principal(void *server_handle,
					     ovsec_kadm_principal_ent_t entry,
					     long mask,
					     char *password)
{
     return kadm5_create_principal(server_handle,
				   (kadm5_principal_ent_t)
				   entry, mask, password);
}


ovsec_kadm_ret_t ovsec_kadm_delete_principal(void *server_handle,
					     krb5_principal principal)
{
     return kadm5_delete_principal(server_handle, principal);
}


ovsec_kadm_ret_t ovsec_kadm_modify_principal(void *server_handle,
					     ovsec_kadm_principal_ent_t entry,
					     long mask)
{
     return kadm5_modify_principal(server_handle,
				   (kadm5_principal_ent_t) entry, mask);
}


ovsec_kadm_ret_t ovsec_kadm_rename_principal(void *server_handle,
					     krb5_principal source,
					     krb5_principal target)
{
     return kadm5_rename_principal(server_handle, source, target);
}

ovsec_kadm_ret_t ovsec_kadm_get_principal(void *server_handle,
					  krb5_principal principal,
					  ovsec_kadm_principal_ent_t *entry)
{
     return kadm5_get_principal(server_handle, principal,
				(kadm5_principal_ent_t *) entry);
}

ovsec_kadm_ret_t ovsec_kadm_chpass_principal(void *server_handle,
					     krb5_principal principal,
					     char *password)
{
     return kadm5_chpass_principal(server_handle, principal, password);
}

ovsec_kadm_ret_t ovsec_kadm_chpass_principal_util(void *server_handle,
						  krb5_principal princ,
						  char *new_pw, 
						  char **ret_pw,
						  char *msg_ret)
{
    /* Oh crap.  Can't change the API without bumping the API version... */
    memset(msg_ret, '\0', 1024);
    return kadm5_chpass_principal_util(server_handle, princ, new_pw,
				       ret_pw, msg_ret, 1024);
}

ovsec_kadm_ret_t ovsec_kadm_randkey_principal(void *server_handle,
					      krb5_principal principal,
					      krb5_keyblock **key)
{
     return kadm5_randkey_principal(server_handle, principal, key);
}

ovsec_kadm_ret_t ovsec_kadm_create_policy(void *server_handle,
					  ovsec_kadm_policy_ent_t entry,
					  long mask)
{
     return kadm5_create_policy(server_handle,
				(kadm5_policy_ent_t) entry, mask); 
}

ovsec_kadm_ret_t ovsec_kadm_delete_policy(void *server_handle,
					  ovsec_kadm_policy_t name)
{
     return kadm5_delete_policy(server_handle, (kadm5_policy_t) name);
}

ovsec_kadm_ret_t ovsec_kadm_modify_policy(void *server_handle,
					  ovsec_kadm_policy_ent_t entry,
					  long mask)
{
     return kadm5_modify_policy(server_handle,
				(kadm5_policy_ent_t) entry, mask); 
}


ovsec_kadm_ret_t ovsec_kadm_get_policy(void *server_handle,
				       ovsec_kadm_policy_t name,
				       ovsec_kadm_policy_ent_t *entry)
{
     return kadm5_get_policy(server_handle, (kadm5_policy_t) name,
			     (kadm5_policy_ent_t *) entry);
}


ovsec_kadm_ret_t ovsec_kadm_free_policy_ent(void *server_handle,
					    ovsec_kadm_policy_ent_t val)
{
     return kadm5_free_policy_ent(server_handle, (kadm5_policy_ent_t) val);
}

ovsec_kadm_ret_t ovsec_kadm_free_name_list(void *server_handle,
					   char **names, int count) 
{
     return kadm5_free_name_list(server_handle, names, count);
}

ovsec_kadm_ret_t
ovsec_kadm_free_principal_ent(void *server_handle,
			      ovsec_kadm_principal_ent_t val)
{
     return kadm5_free_principal_ent(server_handle,
				     (kadm5_principal_ent_t) val);
}

ovsec_kadm_ret_t ovsec_kadm_get_privs(void *server_handle, long *privs)
{
     return kadm5_get_privs(server_handle, privs);
}

ovsec_kadm_ret_t ovsec_kadm_get_principals(void *server_handle,
					   char *exp,
					   char ***princs,
					   int *count)
{
     return kadm5_get_principals(server_handle, exp, princs, count);
}

ovsec_kadm_ret_t ovsec_kadm_get_policies(void *server_handle,
					   char *exp,
					   char ***pols,
					   int *count)
{
     return kadm5_get_policies(server_handle, exp, pols, count);
}


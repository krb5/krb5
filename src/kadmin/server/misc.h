/*
 * Copyright 1994 OpenVision Technologies, Inc., All Rights Reserved
 *
 */

kadm5_ret_t
chpass_principal_wrapper_3(void *server_handle,
			   krb5_principal principal,
			   krb5_boolean keepold,
			   int n_ks_tuple,
			   krb5_key_salt_tuple *ks_tuple,
			   char *password);

kadm5_ret_t
randkey_principal_wrapper_3(void *server_handle,
			    krb5_principal principal,
			    krb5_boolean keepold,
			    int n_ks_tuple,
			    krb5_key_salt_tuple *ks_tuple,
			    krb5_keyblock **keys, int *n_keys);

kadm5_ret_t kadm5_get_principal_v1(void *server_handle,
				   krb5_principal principal, 
				   kadm5_principal_ent_t_v1 *ent);

kadm5_ret_t kadm5_get_policy_v1(void *server_handle, kadm5_policy_t name,
				kadm5_policy_ent_t *ent);


krb5_error_code process_chpw_request(krb5_context context, 
				     void *server_handle, 
				     char *realm, int s, 
				     krb5_keytab keytab, 
				     struct sockaddr_in *sockin, 
				     krb5_data *req, krb5_data *rep);

#ifdef __SVC_HEADER__
void  kadm_1(struct svc_req *, SVCXPRT *);
#endif

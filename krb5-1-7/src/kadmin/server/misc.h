/*
 * Copyright 1994 OpenVision Technologies, Inc., All Rights Reserved
 *
 */

#ifndef _MISC_H
#define _MISC_H 1

typedef struct _krb5_fulladdr {
    krb5_address *	address;
    krb5_ui_4		port;
} krb5_fulladdr;

void
log_badauth(OM_uint32 major, OM_uint32 minor,
	    struct sockaddr_in *addr, char *data);

int
setup_gss_names(struct svc_req *, gss_buffer_desc *,
		gss_buffer_desc *);


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

kadm5_ret_t
schpw_util_wrapper(void *server_handle, krb5_principal client,
		   krb5_principal target, krb5_boolean initial_flag,
		   char *new_pw, char **ret_pw,
		   char *msg_ret, unsigned int msg_len);

kadm5_ret_t check_min_life(void *server_handle, krb5_principal principal,
			   char *msg_ret, unsigned int msg_len);

kadm5_ret_t kadm5_get_principal_v1(void *server_handle,
				   krb5_principal principal, 
				   kadm5_principal_ent_t_v1 *ent);

kadm5_ret_t kadm5_get_policy_v1(void *server_handle, kadm5_policy_t name,
				kadm5_policy_ent_t *ent);


krb5_error_code process_chpw_request(krb5_context context, 
				     void *server_handle, 
				     char *realm,
				     krb5_keytab keytab, 
				     krb5_fulladdr *local_faddr,
				     krb5_fulladdr *remote_faddr,
				     krb5_data *req, krb5_data *rep);

void kadm_1(struct svc_req *, SVCXPRT *);
void krb5_iprop_prog_1(struct svc_req *, SVCXPRT *);

void trunc_name(size_t *len, char **dots);

int
gss_to_krb5_name_1(struct svc_req *rqstp, krb5_context ctx, gss_name_t gss_name,
		   krb5_principal *princ, gss_buffer_t gss_str);


extern volatile int signal_request_exit;
extern volatile int signal_request_hup;

void reset_db(void);

void log_badauth(OM_uint32 major, OM_uint32 minor,
		 struct sockaddr_in *addr, char *data);

/* network.c */
krb5_error_code setup_network(void *handle, const char *prog);
krb5_error_code listen_and_process(void *handle, const char *prog);
krb5_error_code closedown_network(void *handle, const char *prog);


void 
krb5_iprop_prog_1(struct svc_req *rqstp, SVCXPRT *transp);

kadm5_ret_t 
kiprop_get_adm_host_srv_name(krb5_context,
			     const char *,
			     char **);


#endif /* _MISC_H */

#include "k5-int.h"
#include <assert.h>
#include "k5-thread.h"

#include <plugin_manager.h>
#include <plugin_pa.h>

int
preauth_flags(krb5_context context, krb5_preauthtype pa_type);



krb5_error_code KRB5_CALLCONV
process_preauth(krb5_context context, void *plugin_context,
                                       void *request_context, krb5_get_init_creds_opt *opt,
                                       preauth_get_client_data_proc get_data_proc,
                                       struct _krb5_preauth_client_rock *rock, krb5_kdc_req *request,
                                       krb5_data *encoded_request_body,
                                       krb5_data *encoded_previous_request, krb5_pa_data *padata,
                                       krb5_prompter_fct prompter, void *prompter_data,
                                       preauth_get_as_key_proc gak_fct, void *gak_data,
                                       krb5_data *salt, krb5_data *s2kparams, krb5_keyblock *as_key,
                                       krb5_pa_data ***out_padata);
krb5_error_code
kdc_include_padata(krb5_context context, krb5_kdc_req *request,
                                          struct _krb5_db_entry_new *client,
                                          struct _krb5_db_entry_new *server,
                                          preauth_get_entry_data_proc get_entry_proc,
                                          void *pa_module_context, krb5_pa_data *data);
krb5_error_code
kdc_verify_preauth(krb5_context context, struct _krb5_db_entry_new *client,
                                          krb5_data *req_pkt, krb5_kdc_req *request,
                                          krb5_enc_tkt_part *enc_tkt_reply, krb5_pa_data *data,
                                          preauth_get_entry_data_proc get_entry_proc,
                                          void *pa_module_context, void **pa_request_context,
                                          krb5_data **e_data, krb5_authdata ***authz_data);
krb5_error_code
kdc_return_preauth(krb5_context context, krb5_pa_data *padata,
                                          struct _krb5_db_entry_new *client, krb5_data *req_pkt,
                                          krb5_kdc_req *request, krb5_kdc_rep *reply,
                                          struct _krb5_key_data *client_keys,
                                          krb5_keyblock *encrypting_key, krb5_pa_data **send_pa,
                                          preauth_get_entry_data_proc get_entry_proc,
                                          void *pa_module_context, void **pa_request_context);
krb5_error_code
server_free_reqctx(krb5_context kcontext,
                                          void *pa_module_context,
                                          void **pa_request_context);
krb5_error_code
server_init(krb5_context kcontext, void **module_context, const char **realmnames);
void
server_fini(krb5_context kcontext, void *module_context);


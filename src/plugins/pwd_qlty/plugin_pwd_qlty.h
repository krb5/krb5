/*
 * plugin_pwd_qlty.h
 *
 */

#ifndef PLUGIN_PWD_QLTY_H_
#define PLUGIN_PWD_QLTY_H_

#include <plugin_manager.h>
#include <k5-int.h>
#include <admin.h>
#include <server_internal.h>

#define PWD_QLTY_KRB		"plugin_pwd_qlty_krb"
#define PWD_QLTY_KRB_LEN 	19
#define PWD_QLTY_X		"plugin_pwd_qlty_X"
#define PWD_QLTY_X_LEN		17
#define PWD_QLTY_DYN		"plugin_pwd_qlty_DYN"
#define PWD_QLTY_DYN_LEN	19

/* PWD_QLTY API */
typedef struct {
	int version;
	char plugin_id[MAX_PL_NAME_LEN];
	kadm5_ret_t (*pwd_qlty_init)(kadm5_server_handle_t);
	void (*pwd_qlty_cleanup)();
	kadm5_ret_t (*pwd_qlty_check)(kadm5_server_handle_t, char*,
                                      int, kadm5_policy_ent_t, krb5_principal);
} plugin_pwd_qlty;

/* Utility functions */
kadm5_ret_t plugin_pwd_qlty_init(plhandle, kadm5_server_handle_t);
void plugin_pwd_qlty_cleanup(plhandle);
kadm5_ret_t plugin_pwd_qlty_check(plhandle, kadm5_server_handle_t, char*,
                                  int,  kadm5_policy_ent_t, krb5_principal);

#endif /* PLUGIN_PWD_QLTY_H_ */

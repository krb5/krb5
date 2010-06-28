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

#define PWD_QLTY_KRB 0
#define PWD_QLTY_X 1
#define PWD_QLTY_DYN 33

/* PWD_QLTY API */
typedef struct {
	int version;
	int plugin_id;
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

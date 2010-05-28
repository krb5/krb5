/*
 * plugin_pwd_qlty.c
 *
 */
#include <plugin_manager.h>
#include "plugin_pwd_qlty.h"

kadm5_ret_t
plugin_pwd_qlty_check(plhandle handle, kadm5_server_handle_t srv_handle,
                      char *password, int use_policy, kadm5_policy_ent_t pol,
                      krb5_principal principal)
{
    kadm5_ret_t ret = KADM5_OK;
    plugin_pwd_qlty* api = (plugin_pwd_qlty*) handle.api;
    ret = api->pwd_qlty_check(srv_handle, password, use_policy, pol, principal);

    return ret;
}


kadm5_ret_t
plugin_pwd_qlty_init(plhandle handle, kadm5_server_handle_t srv_handle)
{
    kadm5_ret_t ret = KADM5_OK;
    plugin_pwd_qlty* api = (plugin_pwd_qlty*) handle.api;
    ret = api->pwd_qlty_init(srv_handle);

    return ret;
}

void
plugin_pwd_qlty_cleanup(plhandle handle)
{
    return;
}

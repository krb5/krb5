/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "k5-int.h"

#include <plugin_manager.h>
#include <plugin_pwd_qlty.h>
#include "plugin_pwd_qlty_DYN_impl.h"
#include    <string.h>
#include    <ctype.h>


static kadm5_ret_t
_plugin_pwd_qlty_check(kadm5_server_handle_t srv_handle,
             char *password, int use_policy, kadm5_policy_ent_t pol,
             krb5_principal principal)
{


#ifdef DEBUG_PLUGINS
    printf("Plugin pwd qlty DYNAMIC >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
#endif
    return 0;

}

static kadm5_ret_t
_plugin_pwd_qlty_init(kadm5_server_handle_t handle)
{
    return 0;
}

static void
_plugin_pwd_qlty_clean()
{
    return;
}

plhandle
plugin_pwd_qlty_DYN_create()
{
        plhandle handle;
        plugin_pwd_qlty* api = malloc(sizeof(plugin_pwd_qlty));

        memset(api, 0, sizeof(plugin_pwd_qlty));
        api->version = 1;
        api->plugin_id = PWD_QLTY_DYN;
        api->pwd_qlty_init    = _plugin_pwd_qlty_init;
        api->pwd_qlty_check   = _plugin_pwd_qlty_check;
        api->pwd_qlty_cleanup = _plugin_pwd_qlty_clean;
        handle.api = api;

        return handle;
}

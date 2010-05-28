/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "k5-int.h"

#include <plugin_manager.h>
#include <plugin_pwd_qlty.h>
#include "plugin_pwd_qlty_impl.h"
#include    <string.h>
#include    <ctype.h>


#ifdef HESIOD
/* stolen from v4sever/kadm_funcs.c */
static char *
reverse(str)
    char    *str;
{
    static char newstr[80];
    char    *p, *q;
    int     i;

    i = strlen(str);
    if (i >= sizeof(newstr))
        i = sizeof(newstr)-1;
    p = str+i-1;
    q = newstr;
    q[i]='\0';
    for(; i > 0; i--)
        *q++ = *p--;

    return(newstr);
}

static int
str_check_gecos(gecos, pwstr)
    char    *gecos;
    char    *pwstr;
{
    char            *cp, *ncp, *tcp;

    for (cp = gecos; *cp; ) {
        /* Skip past punctuation */
        for (; *cp; cp++)
            if (isalnum(*cp))
                break;
        /* Skip to the end of the word */
        for (ncp = cp; *ncp; ncp++)
            if (!isalnum(*ncp) && *ncp != '\'')
                break;
        /* Delimit end of word */
        if (*ncp)
            *ncp++ = '\0';
        /* Check word to see if it's the password */
        if (*cp) {
            if (!strcasecmp(pwstr, cp))
                return 1;
            tcp = reverse(cp);
            if (!strcasecmp(pwstr, tcp))
                return 1;
            cp = ncp;
        } else
            break;
    }
    return 0;
}
#endif /* HESIOD */


static kadm5_ret_t
_plugin_pwd_qlty_check(kadm5_server_handle_t srv_handle,
             char *password, int use_policy, kadm5_policy_ent_t pol,
             krb5_principal principal)
{
    int     nupper = 0,
        nlower = 0,
        ndigit = 0,
        npunct = 0,
        nspec = 0;
    char    c, *s, *cp;

#ifdef HESIOD
    extern  struct passwd *hes_getpwnam();
    struct  passwd *ent;
#endif
    if(use_policy) {
        if(strlen(password) < (unsigned int)pol->pw_min_length)
            return KADM5_PASS_Q_TOOSHORT;
        s = password;
        while ((c = *s++)) {
            if (islower((unsigned char) c)) {
                nlower = 1;
                continue;
            }
            else if (isupper((unsigned char) c)) {
                nupper = 1;
                continue;
            } else if (isdigit((unsigned char) c)) {
                ndigit = 1;
                continue;
            } else if (ispunct((unsigned char) c)) {
                npunct = 1;
                continue;
            } else {
                nspec = 1;
                continue;
            }
        }
        if ((nupper + nlower + ndigit + npunct + nspec) < pol->pw_min_classes)
            return KADM5_PASS_Q_CLASS;
        if((find_word(password) == KADM5_OK))
            return KADM5_PASS_Q_DICT;
        else {
            int i, n = krb5_princ_size(handle->context, principal);
            cp = krb5_princ_realm(handle->context, principal)->data;
            if (strcasecmp(cp, password) == 0)
                return KADM5_PASS_Q_DICT;
            for (i = 0; i < n ; i++) {
                cp = krb5_princ_component(handle->context, principal, i)->data;
                if (strcasecmp(cp, password) == 0)
                    return KADM5_PASS_Q_DICT;
#ifdef HESIOD
                ent = hes_getpwnam(cp);
                if (ent && ent->pw_gecos)
                    if (str_check_gecos(ent->pw_gecos, password))
                        return KADM5_PASS_Q_DICT; /* XXX new error code? */
#endif
            }
            return KADM5_OK;
        }
    } else {
        if (strlen(password) < 1)
            return KADM5_PASS_Q_TOOSHORT;
    }
    return KADM5_OK;

}

static kadm5_ret_t
_plugin_pwd_qlty_init(kadm5_server_handle_t handle)
{
    init_dict(&handle->params);
    return 0;
}

static void
_plugin_pwd_qlty_clean()
{
    destroy_dict();
    return;
}

plhandle
plugin_pwd_qlty_krb_create()
{
        plhandle handle;
        plugin_pwd_qlty* api = malloc(sizeof(plugin_pwd_qlty));

        memset(api, 0, sizeof(plugin_pwd_qlty));
        api->version = 1;
        api->pwd_qlty_init    = _plugin_pwd_qlty_init;
        api->pwd_qlty_check   = _plugin_pwd_qlty_check;
        api->pwd_qlty_cleanup = _plugin_pwd_qlty_clean;
        handle.api = api;

        return handle;
}

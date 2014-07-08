/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/kdb/ldap/libkdb_ldap/ldap_misc.c */
/*
 * Copyright (c) 2004-2005, Novell, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *   * The copyright holder's name is not used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include "kdb_ldap.h"
#include "ldap_misc.h"
#include "ldap_handle.h"
#include "ldap_err.h"
#include "ldap_principal.h"
#include "princ_xdr.h"
#include "ldap_pwd_policy.h"
#include <time.h>
#include <ctype.h>

#ifdef NEED_STRPTIME_PROTO
extern char *strptime (const char *, const char *, struct tm *);
#endif

static krb5_error_code
remove_overlapping_subtrees(char **listin, char **listop, int *subtcount,
                            int sscope);

/* Linux (GNU Libc) provides a length-limited variant of strdup.
   But all the world's not Linux.  */
#undef strndup
#define strndup my_strndup

static char *
my_strndup(const char *input, size_t limit)
{
    size_t len = strlen(input);
    char *result;
    if (len > limit) {
        result = malloc(1 + limit);
        if (result != NULL) {
            memcpy(result, input, limit);
            result[limit] = 0;
        }
        return result;
    } else
        return strdup(input);
}

/* Get integer or string values from the config section, falling back
   to the default section, then to hard-coded values.  */
static errcode_t
prof_get_integer_def(krb5_context ctx, const char *conf_section,
                     const char *name, int dfl, krb5_ui_4 *out)
{
    errcode_t err;
    int out_temp = 0;

    err = profile_get_integer (ctx->profile,
                               KDB_MODULE_SECTION, conf_section, name,
                               0, &out_temp);
    if (err) {
        k5_setmsg(ctx, err, _("Error reading '%s' attribute: %s"), name,
                  error_message(err));
        return err;
    }
    if (out_temp != 0) {
        *out = out_temp;
        return 0;
    }
    err = profile_get_integer (ctx->profile,
                               KDB_MODULE_DEF_SECTION, name, 0,
                               dfl, &out_temp);
    if (err) {
        k5_setmsg(ctx, err, _("Error reading '%s' attribute: %s"), name,
                  error_message(err));
        return err;
    }
    *out = out_temp;
    return 0;
}

/* Get integer or string values from the config section, falling back
   to the default section, then to hard-coded values.  */
static errcode_t
prof_get_boolean_def(krb5_context ctx, const char *conf_section,
                     const char *name, krb5_boolean dfl, krb5_boolean *out)
{
    errcode_t err;
    int out_temp = 0;

    err = profile_get_boolean(ctx->profile, KDB_MODULE_SECTION, conf_section,
                              name, -1, &out_temp);
    if (err) {
        k5_setmsg(ctx, err, _("Error reading '%s' attribute: %s"), name,
                  error_message(err));
        return err;
    }
    if (out_temp != -1) {
        *out = out_temp;
        return 0;
    }
    err = profile_get_boolean(ctx->profile, KDB_MODULE_DEF_SECTION, name, 0,
                              dfl, &out_temp);
    if (err) {
        k5_setmsg(ctx, err, _("Error reading '%s' attribute: %s"), name,
                  error_message(err));
        return err;
    }
    *out = out_temp;
    return 0;
}

/* We don't have non-null defaults in any of our calls, so don't
   bother with the extra argument.  */
static errcode_t
prof_get_string_def(krb5_context ctx, const char *conf_section,
                    const char *name, char **out)
{
    errcode_t err;

    err = profile_get_string (ctx->profile,
                              KDB_MODULE_SECTION, conf_section, name,
                              0, out);
    if (err) {
        k5_setmsg(ctx, err, _("Error reading '%s' attribute: %s"), name,
                  error_message(err));
        return err;
    }
    if (*out != 0)
        return 0;
    err = profile_get_string (ctx->profile,
                              KDB_MODULE_DEF_SECTION, name, 0,
                              0, out);
    if (err) {
        k5_setmsg(ctx, err, _("Error reading '%s' attribute: %s"), name,
                  error_message(err));
        return err;
    }
    return 0;
}

static krb5_error_code
get_db_opt(const char *input, char **opt_out, char **val_out)
{
    const char *pos;
    char *opt, *val = NULL;
    size_t len;

    *opt_out = *val_out = NULL;
    pos = strchr(input, '=');
    if (pos == NULL) {
        opt = strdup(input);
        if (opt == NULL)
            return ENOMEM;
    } else {
        len = pos - input;
        /* Ignore trailing spaces. */
        while (len > 0 && isspace((unsigned char)input[len - 1]))
            len--;
        opt = strndup(input, len);

        pos++;                  /* Move past '='. */
        while (isspace(*pos))   /* Ignore leading spaces. */
            pos++;
        if (*pos != '\0') {
            val = strdup(pos);
            if (val == NULL) {
                free(opt);
                return ENOMEM;
            }
        }
    }
    *opt_out = opt;
    *val_out = val;
    return 0;
}

static krb5_error_code
add_server_entry(krb5_context context, const char *name)
{
    krb5_ldap_context *lctx = context->dal_handle->db_context;
    krb5_ldap_server_info **sp, **list, *server;
    size_t count = 0;

    /* Allocate list space for the new entry and null terminator. */
    for (sp = lctx->server_info_list; sp != NULL && *sp != NULL; sp++)
        count++;
    list = realloc(lctx->server_info_list, (count + 2) * sizeof(*list));
    if (list == NULL)
        return ENOMEM;
    lctx->server_info_list = list;

    server = calloc(1, sizeof(krb5_ldap_server_info));
    if (server == NULL)
        return ENOMEM;
    server->server_status = NOTSET;
    server->server_name = strdup(name);
    if (server->server_name == NULL) {
        free(server);
        return ENOMEM;
    }
    list[count] = server;
    list[count + 1] = NULL;
    return 0;
}

krb5_error_code
krb5_ldap_parse_db_params(krb5_context context, char **db_args)
{
    char *opt = NULL, *val = NULL;
    krb5_error_code status = 0;
    krb5_ldap_context *lctx = context->dal_handle->db_context;

    if (db_args == NULL)
        return 0;
    for (; *db_args != NULL; db_args++) {
        status = get_db_opt(*db_args, &opt, &val);
        if (status)
            goto cleanup;

        /* Check for options which don't require values. */
        if (!strcmp(opt, "temporary")) {
            /* "temporary" is passed by kdb5_util load without -update,
             * which we don't support. */
            status = EINVAL;
            k5_setmsg(context, status,
                      _("KDB module requires -update argument"));
            goto cleanup;
        }

        if (val == NULL) {
            status = EINVAL;
            k5_setmsg(context, status, _("'%s' value missing"), opt);
            goto cleanup;
        }

        /* Check for options which do require arguments. */
        if (!strcmp(opt, "binddn")) {
            free(lctx->bind_dn);
            lctx->bind_dn = strdup(val);
            if (lctx->bind_dn == NULL) {
                status = ENOMEM;
                goto cleanup;
            }
        } else if (!strcmp(opt, "nconns")) {
            lctx->max_server_conns = atoi(val) ? atoi(val) :
                DEFAULT_CONNS_PER_SERVER;
        } else if (!strcmp(opt, "bindpwd")) {
            free(lctx->bind_pwd);
            lctx->bind_pwd = strdup(val);
            if (lctx->bind_pwd == NULL) {
                status = ENOMEM;
                goto cleanup;
            }
        } else if (!strcmp(opt, "host")) {
            status = add_server_entry(context, val);
            if (status)
                goto cleanup;
        } else if (!strcmp(opt, "debug")) {
            lctx->ldap_debug = atoi(val);
        } else {
            status = EINVAL;
            k5_setmsg(context, status, _("unknown option '%s'"), opt);
            goto cleanup;
        }

        free(opt);
        free(val);
        opt = val = NULL;
    }

cleanup:
    free(opt);
    free(val);
    return status;
}

/*
 * This function reads the parameters from the krb5.conf file. The
 * parameters read here are DAL-LDAP specific attributes. Some of
 * these are ldap_server ....
 */
krb5_error_code
krb5_ldap_read_server_params(krb5_context context, char *conf_section,
                             int srv_type)
{
    char                        *tempval=NULL, *save_ptr=NULL, *item=NULL;
    const char                  *delims="\t\n\f\v\r ,";
    krb5_error_code             st=0;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;

    dal_handle = context->dal_handle;
    ldap_context = (krb5_ldap_context *) dal_handle->db_context;

    /* copy the conf_section into ldap_context for later use */
    if (conf_section) {
        ldap_context->conf_section = strdup (conf_section);
        if (ldap_context->conf_section == NULL) {
            st = ENOMEM;
            goto cleanup;
        }
    }

    /* initialize the mutexs and condition variable */
    /* this portion logically doesn't fit here should be moved appropriately */

    /* this mutex is used in ldap reconnection pool */
    if (k5_mutex_init(&(ldap_context->hndl_lock)) != 0) {
        st = KRB5_KDB_SERVER_INTERNAL_ERR;
#if 0
        st = -1;
        krb5_ldap_dal_err_funcp(context, krb5_err_have_str, st,
                                "k5_mutex_init failed");
#endif
        goto cleanup;
    }

    /*
     * If max_server_conns is not set read it from database module
     * section of conf file this parameter defines maximum ldap
     * connections per ldap server.
     */
    if (ldap_context->max_server_conns == 0) {
        st = prof_get_integer_def (context, conf_section,
                                   KRB5_CONF_LDAP_CONNS_PER_SERVER,
                                   DEFAULT_CONNS_PER_SERVER,
                                   &ldap_context->max_server_conns);
        if (st)
            goto cleanup;
    }

    if (ldap_context->max_server_conns < 2) {
        st = EINVAL;
        k5_setmsg(context, st,
                  _("Minimum connections required per server is 2"));
        goto cleanup;
    }

    /*
     * If the bind dn is not set read it from the database module
     * section of conf file this paramter is populated by one of the
     * KDC, ADMIN or PASSWD dn to be used to connect to LDAP
     * server.  The srv_type decides which dn to read.
     */
    if (ldap_context->bind_dn == NULL) {
        char *name = 0;
        if (srv_type == KRB5_KDB_SRV_TYPE_KDC)
            name = KRB5_CONF_LDAP_KDC_DN;
        else if (srv_type == KRB5_KDB_SRV_TYPE_ADMIN)
            name = KRB5_CONF_LDAP_KADMIND_DN;

        if (name) {
            st = prof_get_string_def (context, conf_section, name,
                                      &ldap_context->bind_dn);
            if (st)
                goto cleanup;
        }
    }

    /*
     * Read service_password_file parameter from database module
     * section of conf file this file contains stashed passwords of
     * the KDC, ADMIN and PASSWD dns.
     */
    if (ldap_context->service_password_file == NULL) {
        st = prof_get_string_def (context, conf_section,
                                  KRB5_CONF_LDAP_SERVICE_PASSWORD_FILE,
                                  &ldap_context->service_password_file);
        if (st)
            goto cleanup;
    }

    /*
     * If the ldap server parameter is not set read the list of ldap
     * servers from the database module section of the conf file.
     */

    if (ldap_context->server_info_list == NULL) {
        if ((st=profile_get_string(context->profile, KDB_MODULE_SECTION, conf_section,
                                   KRB5_CONF_LDAP_SERVERS, NULL, &tempval)) != 0) {
            k5_setmsg(context, st,
                      _("Error reading 'ldap_servers' attribute"));
            goto cleanup;
        }

        if (tempval == NULL) {
            st = add_server_entry(context, "ldapi://");
            if (st)
                goto cleanup;
        } else {
            item = strtok_r(tempval, delims, &save_ptr);
            while (item != NULL) {
                st = add_server_entry(context, item);
                if (st)
                    goto cleanup;
                item = strtok_r(NULL,delims,&save_ptr);
            }
            profile_release_string(tempval);
        }
    }

    if ((st = prof_get_boolean_def(context, conf_section,
                                   KRB5_CONF_DISABLE_LAST_SUCCESS, FALSE,
                                   &ldap_context->disable_last_success)))
        goto cleanup;

    if ((st = prof_get_boolean_def(context, conf_section,
                                   KRB5_CONF_DISABLE_LOCKOUT, FALSE,
                                   &ldap_context->disable_lockout)))
        goto cleanup;

cleanup:
    return(st);
}

/*
 * This function frees the krb5_ldap_context structure members.
 */

krb5_error_code
krb5_ldap_free_server_context_params(krb5_ldap_context *ldap_context)
{
    int                         i=0;
    krb5_ldap_server_handle     *ldap_server_handle=NULL, *next_ldap_server_handle=NULL;

    if (ldap_context == NULL)
        return 0;

    /* Free all ldap servers list and the ldap handles associated with
       the ldap server.  */
    if (ldap_context->server_info_list) {
        while (ldap_context->server_info_list[i]) {
            if (ldap_context->server_info_list[i]->server_name) {
                free (ldap_context->server_info_list[i]->server_name);
            }
            if (ldap_context->server_info_list[i]->ldap_server_handles) {
                ldap_server_handle = ldap_context->server_info_list[i]->ldap_server_handles;
                while (ldap_server_handle) {
                    ldap_unbind_ext_s(ldap_server_handle->ldap_handle, NULL, NULL);
                    ldap_server_handle->ldap_handle = NULL;
                    next_ldap_server_handle = ldap_server_handle->next;
                    free(ldap_server_handle);
                    ldap_server_handle = next_ldap_server_handle;
                }
            }
            free(ldap_context->server_info_list[i]);
            i++;
        }
        free(ldap_context->server_info_list);
    }

    if (ldap_context->conf_section != NULL) {
        free(ldap_context->conf_section);
        ldap_context->conf_section = NULL;
    }

    if (ldap_context->bind_dn != NULL) {
        free(ldap_context->bind_dn);
        ldap_context->bind_dn = NULL;
    }

    if (ldap_context->bind_pwd != NULL) {
        memset(ldap_context->bind_pwd, 0, strlen(ldap_context->bind_pwd));
        free(ldap_context->bind_pwd);
        ldap_context->bind_pwd = NULL;
    }

    if (ldap_context->service_password_file != NULL) {
        free(ldap_context->service_password_file);
        ldap_context->service_password_file = NULL;
    }

    if (ldap_context->certificates) {
        i=0;
        while (ldap_context->certificates[i] != NULL) {
            free(ldap_context->certificates[i]->certificate);
            free(ldap_context->certificates[i]);
            ++i;
        }
        free(ldap_context->certificates);
    }

    return(0);
}

krb5_error_code
krb5_ldap_free_server_params(krb5_ldap_context *ldap_context)
{
    if (ldap_context == NULL)
        return 0;

    krb5_ldap_free_server_context_params(ldap_context);

    k5_mutex_destroy(&ldap_context->hndl_lock);
    free(ldap_context);
    return(0);
}

/*
 * check to see if the principal belongs to the default realm.
 * The default realm is present in the krb5_ldap_context structure.
 * The principal has a realm portion. This realm portion is compared with the default realm
 * to check whether the principal belong to the default realm.
 * Return 0 if principal belongs to default realm else 1.
 */

krb5_error_code
is_principal_in_realm(krb5_ldap_context *ldap_context,
                      krb5_const_principal searchfor)
{
    char                        *defrealm=NULL;

#define FIND_MAX(a,b) ((a) > (b) ? (a) : (b))

    defrealm = ldap_context->lrparams->realm_name;

    /*
     * Care should be taken for inter-realm principals as the default
     * realm can exist in the realm part of the principal name or can
     * also exist in the second portion of the name part.  However, if
     * the default realm exist in the second part of the principal
     * portion, then the first portion of the principal name SHOULD be
     * "krbtgt".  All this check is done in the immediate block.
     */
    if (searchfor->length == 2) {
        if (data_eq_string(searchfor->data[0], "krbtgt") &&
            data_eq_string(searchfor->data[1], defrealm))
            return 0;
    }

    /* first check the length, if they are not equal, then they are not same */
    if (strlen(defrealm) != searchfor->realm.length)
        return 1;

    /* if the length is equal, check for the contents */
    if (strncmp(defrealm, searchfor->realm.data,
                searchfor->realm.length) != 0)
        return 1;
    /* if we are here, then the realm portions match, return 0 */
    return 0;
}


/*
 * Deduce the subtree information from the context. A realm can have
 * multiple subtrees.
 * 1. the Realm container
 * 2. the actual subtrees associated with the Realm
 *
 * However, there are some conditions to be considered to deduce the
 * actual subtree/s associated with the realm.  The conditions are as
 * follows:
 * 1. If the subtree information of the Realm is [Root] or NULL (that
 *    is internal a [Root]) then the realm has only one subtree
 *    i.e [Root], i.e. whole of the tree.
 * 2. If the subtree information of the Realm is missing/absent, then the
 *    realm has only one, i.e., the Realm container.  NOTE: In all cases
 *    Realm container SHOULD be the one among the subtrees or the only
 *    one subtree.
 * 3. The subtree information of the realm is overlapping the realm
 *    container of the realm, then the realm has only one subtree and
 *    it is the subtree information associated with the realm.
 */
krb5_error_code
krb5_get_subtree_info(krb5_ldap_context *ldap_context, char ***subtreearr,
                      unsigned int *ntree)
{
    int                         st=0, i=0, subtreecount=0;
    int                         ncount=0, search_scope=0;
    char                        **subtree=NULL, *realm_cont_dn=NULL;
    char                        **subtarr=NULL;
    char                        *containerref=NULL;
    char                        **newsubtree=NULL;

    containerref = ldap_context->lrparams->containerref;
    subtree = ldap_context->lrparams->subtree;
    realm_cont_dn = ldap_context->lrparams->realmdn;
    subtreecount = ldap_context->lrparams->subtreecount;
    search_scope = ldap_context->lrparams->search_scope;

    subtarr = (char **) malloc(sizeof(char *) * (subtreecount + 1 /*realm dn*/ + 1 /*containerref*/ + 1));
    if (subtarr == NULL) {
        st = ENOMEM;
        goto cleanup;
    }
    memset(subtarr, 0, (sizeof(char *) * (subtreecount+1+1+1)));

    /* get the complete subtree list */
    for (i=0; i<subtreecount && subtree[i]!=NULL; i++) {
        subtarr[i] = strdup(subtree[i]);
        if (subtarr[i] == NULL) {
            st = ENOMEM;
            goto cleanup;
        }
    }

    subtarr[i] = strdup(realm_cont_dn);
    if (subtarr[i++] == NULL) {
        st = ENOMEM;
        goto cleanup;
    }

    if (containerref != NULL) {
        subtarr[i] = strdup(containerref);
        if (subtarr[i++] == NULL) {
            st = ENOMEM;
            goto cleanup;
        }
    }

    ncount = i;
    newsubtree = (char **) malloc(sizeof(char *) * (ncount + 1));
    if (newsubtree == NULL) {
        st = ENOMEM;
        goto cleanup;
    }
    memset(newsubtree, 0, (sizeof(char *) * (ncount+1)));
    if ((st = remove_overlapping_subtrees(subtarr, newsubtree, &ncount,
                                          search_scope)) != 0) {
        goto cleanup;
    }

    *ntree = ncount;
    *subtreearr = newsubtree;

cleanup:
    if (subtarr != NULL) {
        for (i=0; subtarr[i] != NULL; i++)
            free(subtarr[i]);
        free(subtarr);
    }

    if (st != 0) {
        if (newsubtree != NULL) {
            for (i=0; newsubtree[i] != NULL; i++)
                free(newsubtree[i]);
            free(newsubtree);
        }
    }
    return st;
}

/*
 * This function appends the content with a type into the tl_data
 * structure.  Based on the type the length of the content is either
 * pre-defined or computed from the content.  Returns 0 in case of
 * success and 1 if the type associated with the content is undefined.
 */

krb5_error_code
store_tl_data(krb5_tl_data *tl_data, int tl_type, void *value)
{
    unsigned int                currlen=0, tldatalen=0;
    unsigned char               *curr=NULL;
    void                        *reallocptr=NULL;

    tl_data->tl_data_type = KDB_TL_USER_INFO;
    switch (tl_type) {
    case KDB_TL_PRINCCOUNT:
    case KDB_TL_PRINCTYPE:
    case KDB_TL_MASK:
    {
        int *iptr = (int *)value;
        int ivalue = *iptr;

        currlen = tl_data->tl_data_length;
        tl_data->tl_data_length += 1 + 2 + 2;
        /* allocate required memory */
        reallocptr = tl_data->tl_data_contents;
        tl_data->tl_data_contents = realloc(tl_data->tl_data_contents,
                                            tl_data->tl_data_length);
        if (tl_data->tl_data_contents == NULL) {
            if (reallocptr)
                free (reallocptr);
            return ENOMEM;
        }
        curr = (tl_data->tl_data_contents + currlen);

        /* store the tl_type value */
        memset(curr, tl_type, 1);
        curr += 1;
        /* store the content length */
        tldatalen = 2;
        STORE16_INT(curr, tldatalen);
        curr += 2;
        /* store the content */
        STORE16_INT(curr, ivalue);
        curr += 2;
        break;
    }

    case KDB_TL_USERDN:
    case KDB_TL_LINKDN:
    {
        char *cptr = (char *)value;

        currlen = tl_data->tl_data_length;
        tl_data->tl_data_length += 1 + 2 + strlen(cptr);
        /* allocate required memory */
        reallocptr = tl_data->tl_data_contents;
        tl_data->tl_data_contents = realloc(tl_data->tl_data_contents,
                                            tl_data->tl_data_length);
        if (tl_data->tl_data_contents == NULL) {
            if (reallocptr)
                free (reallocptr);
            return ENOMEM;
        }
        curr = (tl_data->tl_data_contents + currlen);

        /* store the tl_type value */
        memset(curr, tl_type, 1);
        curr += 1;
        /* store the content length */
        tldatalen = strlen(cptr);
        STORE16_INT(curr, tldatalen);
        curr += 2;
        /* store the content */
        memcpy(curr, cptr, tldatalen);
        curr += tldatalen;
        break;
    }

    default:
        return 1;

    }
    return 0;
}

/*
 * This function scans the tl_data structure to get the value of a
 * type defined by the tl_type (second parameter).  The tl_data
 * structure has all the data in the tl_data_contents member.  The
 * format of the tl_data_contents is as follows.  The first byte
 * defines the type of the content that follows.  The next 2 bytes
 * define the size n (in terms of bytes) of the content that
 * follows.  The next n bytes define the content itself.
 */

krb5_error_code
decode_tl_data(krb5_tl_data *tl_data, int tl_type, void **data)
{
    int                         subtype=0, i=0, limit=10;
    unsigned int                sublen=0;
    unsigned char               *curr=NULL;
    int                         *intptr=NULL;
    long                        *longptr=NULL;
    char                        *DN=NULL, **DNarr=NULL;
    krb5_error_code             st=-1;

    *data = NULL;

    curr = tl_data->tl_data_contents;
    while (curr < (tl_data->tl_data_contents + tl_data->tl_data_length)) {

        /* get the type of the content */
        subtype = (int) curr[0];
        /* forward by 1 byte*/
        curr += 1;

        if (subtype == tl_type) {
            switch (subtype) {

            case KDB_TL_PRINCCOUNT:
            case KDB_TL_PRINCTYPE:
            case KDB_TL_MASK:
                /* get the length of the content */
                UNSTORE16_INT(curr, sublen);
                /* forward by 2 bytes */
                curr += 2;
                /* get the actual content */
                if (sublen == 2) {
                    /* intptr = malloc(sublen);   */
                    intptr = malloc(sizeof(krb5_int32));
                    if (intptr == NULL)
                        return ENOMEM;
                    memset(intptr, 0, sublen);
                    UNSTORE16_INT(curr, (*intptr));
                    *data = intptr;
                } else {
                    longptr = malloc(sublen);
                    if (longptr == NULL)
                        return ENOMEM;
                    memset(longptr, 0, sublen);
                    UNSTORE32_INT(curr, (*longptr));
                    *data = longptr;
                }
                curr += sublen;
                st = 0;
                return st;
                break;

            case KDB_TL_CONTAINERDN:
            case KDB_TL_USERDN:
                /* get the length of the content */
                UNSTORE16_INT(curr, sublen);
                /* forward by 2 bytes */
                curr += 2;
                DN = k5memdup0(curr, sublen, &st);
                if (DN == NULL)
                    return st;
                *data = DN;
                curr += sublen;
                st = 0;
                return st;
                break;

            case KDB_TL_LINKDN:
                if (DNarr == NULL) {
                    DNarr = calloc(limit, sizeof(char *));
                    if (DNarr == NULL)
                        return ENOMEM;
                }
                if (i == limit-1) {
                    limit *= 2;
                    DNarr = realloc(DNarr, sizeof(char *) * (limit));
                    if (DNarr == NULL)
                        return ENOMEM;
                }

                /* get the length of the content */
                UNSTORE16_INT(curr, sublen);
                /* forward by 2 bytes */
                curr += 2;
                DNarr[i] = k5memdup0(curr, sublen, &st);
                if (DNarr[i] == NULL)
                    return st;
                ++i;
                curr += sublen;
                *data = DNarr;
                st=0;
                break;
            }
        } else {
            /* move to the current content block */
            UNSTORE16_INT(curr, sublen);
            curr += 2 + sublen;
        }
    }
    return st;
}

/*
 * wrapper routines for decode_tl_data
 */
static krb5_error_code
krb5_get_int_from_tl_data(krb5_context context, krb5_db_entry *entries,
                          int type, int *intval)
{
    krb5_error_code             st=0;
    krb5_tl_data                tl_data;
    void                        *voidptr=NULL;
    int                         *intptr=NULL;

    tl_data.tl_data_type = KDB_TL_USER_INFO;
    if (((st=krb5_dbe_lookup_tl_data(context, entries, &tl_data)) != 0) || tl_data.tl_data_length == 0)
        goto cleanup;

    if (decode_tl_data(&tl_data, type, &voidptr) == 0) {
        intptr = (int *) voidptr;
        *intval = *intptr;
        free(intptr);
    }

cleanup:
    return st;
}

/*
 * Get the mask representing the attributes set on the directory
 * object (user, policy ...).
 */
krb5_error_code
krb5_get_attributes_mask(krb5_context context, krb5_db_entry *entries,
                         int *mask)
{
    return krb5_get_int_from_tl_data(context, entries, KDB_TL_MASK, mask);
}

krb5_error_code
krb5_get_princ_type(krb5_context context, krb5_db_entry *entries, int *ptype)
{
    return krb5_get_int_from_tl_data(context, entries, KDB_TL_PRINCTYPE, ptype);
}

krb5_error_code
krb5_get_princ_count(krb5_context context, krb5_db_entry *entries, int *pcount)
{
    return krb5_get_int_from_tl_data(context, entries, KDB_TL_PRINCCOUNT, pcount);
}

krb5_error_code
krb5_get_linkdn(krb5_context context, krb5_db_entry *entries, char ***link_dn)
{
    krb5_error_code             st=0;
    krb5_tl_data                tl_data;
    void                        *voidptr=NULL;

    *link_dn = NULL;
    tl_data.tl_data_type = KDB_TL_USER_INFO;
    if (((st=krb5_dbe_lookup_tl_data(context, entries, &tl_data)) != 0) || tl_data.tl_data_length == 0)
        goto cleanup;

    if (decode_tl_data(&tl_data, KDB_TL_LINKDN, &voidptr) == 0) {
        *link_dn = (char **) voidptr;
    }

cleanup:
    return st;
}

static krb5_error_code
krb5_get_str_from_tl_data(krb5_context context, krb5_db_entry *entries,
                          int type, char **strval)
{
    krb5_error_code             st=0;
    krb5_tl_data                tl_data;
    void                        *voidptr=NULL;

    if (type != KDB_TL_USERDN && type != KDB_TL_CONTAINERDN) {
        st = EINVAL;
        goto cleanup;
    }

    tl_data.tl_data_type = KDB_TL_USER_INFO;
    if (((st=krb5_dbe_lookup_tl_data(context, entries, &tl_data)) != 0) || tl_data.tl_data_length == 0)
        goto cleanup;

    if (decode_tl_data(&tl_data, type, &voidptr) == 0) {
        *strval = (char *) voidptr;
    }

cleanup:
    return st;
}

krb5_error_code
krb5_get_userdn(krb5_context context, krb5_db_entry *entries, char **userdn)
{
    *userdn = NULL;
    return krb5_get_str_from_tl_data(context, entries, KDB_TL_USERDN, userdn);
}

krb5_error_code
krb5_get_containerdn(krb5_context context, krb5_db_entry *entries,
                     char **containerdn)
{
    *containerdn = NULL;
    return krb5_get_str_from_tl_data(context, entries, KDB_TL_CONTAINERDN, containerdn);
}

/*
 * This function reads the attribute values (if the attribute is
 * non-null) from the dn.  The read attribute values is compared
 * aganist the attrvalues passed to the function and a bit mask is set
 * for all the matching attributes (attributes existing in both list).
 * The bit to be set is selected such that the index of the attribute
 * in the attrvalues parameter is the position of the bit.  For ex:
 * the first element in the attrvalues is present in both list shall
 * set the LSB of the bit mask.
 *
 * In case if either the attribute or the attrvalues parameter to the
 * function is NULL, then the existence of the object is considered
 * and appropriate status is returned back.
 */

krb5_error_code
checkattributevalue(LDAP *ld, char *dn, char *attribute, char **attrvalues,
                    int *mask)
{
    int                         st=0, one=1;
    char                        **values=NULL, *attributes[2] = {NULL};
    LDAPMessage                 *result=NULL, *entry=NULL;

    if (strlen(dn) == 0) {
        st = set_ldap_error(0, LDAP_NO_SUCH_OBJECT, OP_SEARCH);
        return st;
    }

    attributes[0] = attribute;

    /* read the attribute values from the dn */
    if ((st = ldap_search_ext_s(ld,
                                dn,
                                LDAP_SCOPE_BASE,
                                0,
                                attributes,
                                0,
                                NULL,
                                NULL,
                                &timelimit,
                                LDAP_NO_LIMIT,
                                &result)) != LDAP_SUCCESS) {
        st = set_ldap_error(0, st, OP_SEARCH);
        return st;
    }

    /*
     * If the attribute/attrvalues is NULL, then check for the
     * existence of the object alone.
     */
    if (attribute == NULL || attrvalues == NULL)
        goto cleanup;

    /* reset the bit mask */
    *mask = 0;

    if ((entry=ldap_first_entry(ld, result)) != NULL) {
        /* read the attribute values */
        if ((values=ldap_get_values(ld, entry, attribute)) != NULL) {
            int i,j;

            /*
             * Compare the read attribute values with the attrvalues
             * array and set the appropriate bit mask.
             */
            for (j=0; attrvalues[j]; ++j) {
                for (i=0; values[i]; ++i) {
                    if (strcasecmp(values[i], attrvalues[j]) == 0) {
                        *mask |= (one<<j);
                        break;
                    }
                }
            }
            ldap_value_free(values);
        }
    }

cleanup:
    ldap_msgfree(result);
    return st;
}


static krb5_error_code
getepochtime(char *strtime, krb5_timestamp *epochtime)
{
    struct tm           tme;

    memset(&tme, 0, sizeof(tme));
    if (strptime(strtime,"%Y%m%d%H%M%SZ", &tme) == NULL) {
        *epochtime = 0;
        return EINVAL;
    }
    *epochtime = krb5int_gmt_mktime(&tme);
    return 0;
}

/*
 * krb5_ldap_get_value() - get the integer value of the attribute
 * Returns, 0 if the attribute is present, 1 if the attribute is missing.
 * The retval is 0 if the attribute is missing.
 */

krb5_error_code
krb5_ldap_get_value(LDAP *ld, LDAPMessage *ent, char *attribute, int *retval)
{
    char                           **values=NULL;

    *retval = 0;
    values=ldap_get_values(ld, ent, attribute);
    if (values != NULL) {
        if (values[0] != NULL)
            *retval = atoi(values[0]);
        ldap_value_free(values);
        return 0;
    }
    return 1;
}

/*
 * krb5_ldap_get_string() - Returns the first string of the
 * attribute.  Intended to
 *
 *
 */
krb5_error_code
krb5_ldap_get_string(LDAP *ld, LDAPMessage *ent, char *attribute,
                     char **retstr, krb5_boolean *attr_present)
{
    char                           **values=NULL;
    krb5_error_code                st=0;

    *retstr = NULL;
    if (attr_present != NULL)
        *attr_present = FALSE;

    values=ldap_get_values(ld, ent, attribute);
    if (values != NULL) {
        if (values[0] != NULL) {
            if (attr_present!= NULL)
                *attr_present = TRUE;
            *retstr = strdup(values[0]);
            if (*retstr == NULL)
                st = ENOMEM;
        }
        ldap_value_free(values);
    }
    return st;
}

/*
 * krb5_ldap_get_strings() - Returns all the values
 * of the attribute.
 */
krb5_error_code
krb5_ldap_get_strings(LDAP *ld, LDAPMessage *ent, char *attribute,
                      char ***retarr, krb5_boolean *attr_present)
{
    char                        **values=NULL;
    krb5_error_code             st=0;
    unsigned int                i=0, count=0;

    *retarr = NULL;
    if (attr_present != NULL)
        *attr_present = FALSE;

    values=ldap_get_values(ld, ent, attribute);
    if (values != NULL) {
        if (attr_present != NULL)
            *attr_present = TRUE;

        count = ldap_count_values(values);
        *retarr  = (char **) calloc(count+1, sizeof(char *));
        if (*retarr == NULL) {
            st = ENOMEM;
            return st;
        }
        for (i=0; i< count; ++i) {
            (*retarr)[i] = strdup(values[i]);
            if ((*retarr)[i] == NULL) {
                st = ENOMEM;
                goto cleanup;
            }
        }
        ldap_value_free(values);
    }

cleanup:
    if (st != 0) {
        if (*retarr != NULL) {
            for (i=0; i< count; ++i)
                if ((*retarr)[i] != NULL)
                    free ((*retarr)[i]);
            free (*retarr);
        }
    }
    return st;
}

krb5_error_code
krb5_ldap_get_time(LDAP *ld, LDAPMessage *ent, char *attribute,
                   krb5_timestamp *rettime, krb5_boolean *attr_present)
{
    char                         **values=NULL;
    krb5_error_code              st=0;

    *rettime = 0;
    *attr_present = FALSE;

    values=ldap_get_values(ld, ent, attribute);
    if (values != NULL) {
        if (values[0] != NULL) {
            *attr_present = TRUE;
            st = getepochtime(values[0], rettime);
        }
        ldap_value_free(values);
    }
    return st;
}

/*
 * Function to allocate, set the values of LDAPMod structure. The
 * LDAPMod structure is then added to the array at the ind
 */

krb5_error_code
krb5_add_member(LDAPMod ***mods, int *count)
{
    int i=0;
    LDAPMod **lmods=NULL;

    if ((*mods) != NULL) {
        for (;(*mods)[i] != NULL; ++i)
            ;
    }
    lmods = (LDAPMod **) realloc((*mods), (2+i) * sizeof(LDAPMod *));
    if (lmods == NULL)
        return ENOMEM;

    *mods = lmods;
    (*mods)[i+1] = NULL;
    (*mods)[i] = (LDAPMod *) calloc(1, sizeof (LDAPMod));
    if ((*mods)[i] == NULL)
        return ENOMEM;
    *count = i;
    return 0;
}

krb5_error_code
krb5_add_str_mem_ldap_mod(LDAPMod ***mods, char *attribute, int op,
                          char **values)
{
    int i=0, j=0;
    krb5_error_code   st=0;

    if ((st=krb5_add_member(mods, &i)) != 0)
        return st;

    (*mods)[i]->mod_type = strdup(attribute);
    if ((*mods)[i]->mod_type == NULL)
        return ENOMEM;
    (*mods)[i]->mod_op = op;

    (*mods)[i]->mod_values = NULL;

    if (values != NULL) {
        for (j=0; values[j] != NULL; ++j)
            ;
        (*mods)[i]->mod_values = malloc (sizeof(char *) * (j+1));
        if ((*mods)[i]->mod_values == NULL)
            return ENOMEM;

        for (j=0; values[j] != NULL; ++j) {
            (*mods)[i]->mod_values[j] = strdup(values[j]);
            if ((*mods)[i]->mod_values[j] == NULL)
                return ENOMEM;
        }
        (*mods)[i]->mod_values[j] = NULL;
    }
    return 0;
}

krb5_error_code
krb5_add_ber_mem_ldap_mod(LDAPMod ***mods, char *attribute, int op,
                          struct berval **ber_values)
{
    int i=0, j=0;
    krb5_error_code   st=0;

    if ((st=krb5_add_member(mods, &i)) != 0)
        return st;

    (*mods)[i]->mod_type = strdup(attribute);
    if ((*mods)[i]->mod_type == NULL)
        return ENOMEM;
    (*mods)[i]->mod_op = op;

    for (j=0; ber_values[j] != NULL; ++j)
        ;
    (*mods)[i]->mod_bvalues = malloc (sizeof(struct berval *) * (j+1));
    if ((*mods)[i]->mod_bvalues == NULL)
        return ENOMEM;

    for (j=0; ber_values[j] != NULL; ++j) {
        (*mods)[i]->mod_bvalues[j] = calloc(1, sizeof(struct berval));
        if ((*mods)[i]->mod_bvalues[j] == NULL)
            return ENOMEM;

        (*mods)[i]->mod_bvalues[j]->bv_len = ber_values[j]->bv_len;
        (*mods)[i]->mod_bvalues[j]->bv_val =
            k5memdup(ber_values[j]->bv_val, ber_values[j]->bv_len, &st);
        if ((*mods)[i]->mod_bvalues[j]->bv_val == NULL)
            return ENOMEM;
    }
    (*mods)[i]->mod_bvalues[j] = NULL;
    return 0;
}

static inline char *
format_d (int val)
{
    char tmpbuf[2+3*sizeof(val)];
    snprintf(tmpbuf, sizeof(tmpbuf), "%d", val);
    return strdup(tmpbuf);
}

krb5_error_code
krb5_add_int_mem_ldap_mod(LDAPMod ***mods, char *attribute, int op, int value)
{
    int i=0;
    krb5_error_code      st=0;

    if ((st=krb5_add_member(mods, &i)) != 0)
        return st;

    (*mods)[i]->mod_type = strdup(attribute);
    if ((*mods)[i]->mod_type == NULL)
        return ENOMEM;

    (*mods)[i]->mod_op = op;
    (*mods)[i]->mod_values = calloc (2, sizeof(char *));
    if (((*mods)[i]->mod_values[0] = format_d(value)) == NULL)
        return ENOMEM;
    return 0;
}

krb5_error_code
krb5_ldap_lock(krb5_context kcontext, int mode)
{
    krb5_error_code status = KRB5_PLUGIN_OP_NOTSUPP;
    k5_setmsg(kcontext, status, "LDAP %s", error_message(status));
    return status;
}

krb5_error_code
krb5_ldap_unlock(krb5_context kcontext)
{
    krb5_error_code status = KRB5_PLUGIN_OP_NOTSUPP;
    k5_setmsg(kcontext, status, "LDAP %s", error_message(status));
    return status;
}


/*
 * Get the number of times an object has been referred to in a realm. this is
 * needed to find out if deleting the attribute will cause dangling links.
 *
 * An LDAP handle may be optionally specified to prevent race condition - there
 * are a limited number of LDAP handles.
 */
krb5_error_code
krb5_ldap_get_reference_count(krb5_context context, char *dn, char *refattr,
                              int *count, LDAP *ld)
{
    int                         st = 0, tempst = 0, gothandle = 0;
    unsigned int                i, ntrees;
    char                        *refcntattr[2];
    char                        *filter = NULL;
    char                        **subtree = NULL, *ptr = NULL;
    kdb5_dal_handle             *dal_handle = NULL;
    krb5_ldap_context           *ldap_context = NULL;
    krb5_ldap_server_handle     *ldap_server_handle = NULL;
    LDAPMessage                 *result = NULL;


    if (dn == NULL || refattr == NULL) {
        st = EINVAL;
        goto cleanup;
    }

    SETUP_CONTEXT();
    if (ld == NULL) {
        GET_HANDLE();
        gothandle = 1;
    }

    refcntattr [0] = refattr;
    refcntattr [1] = NULL;

    ptr = ldap_filter_correct (dn);
    if (ptr == NULL) {
        st = ENOMEM;
        goto cleanup;
    }

    if (asprintf (&filter, "%s=%s", refattr, ptr) < 0) {
        filter = NULL;
        st = ENOMEM;
        goto cleanup;
    }

    if ((st = krb5_get_subtree_info(ldap_context, &subtree, &ntrees)) != 0)
        goto cleanup;

    for (i = 0, *count = 0; i < ntrees; i++) {
        int n;

        LDAP_SEARCH(subtree[i],
                    LDAP_SCOPE_SUBTREE,
                    filter,
                    refcntattr);
        n = ldap_count_entries (ld, result);
        if (n == -1) {
            int ret, errcode = 0;
            ret = ldap_parse_result (ld, result, &errcode, NULL, NULL, NULL, NULL, 0);
            if (ret != LDAP_SUCCESS)
                errcode = ret;
            st = translate_ldap_error (errcode, OP_SEARCH);
            goto cleanup;
        }

        ldap_msgfree(result);
        result = NULL;

        *count += n;
    }

cleanup:
    if (filter != NULL)
        free (filter);

    if (result != NULL)
        ldap_msgfree (result);

    if (subtree != NULL) {
        for (i = 0; i < ntrees; i++)
            free (subtree[i]);
        free (subtree);
    }

    if (ptr != NULL)
        free (ptr);

    if (gothandle == 1)
        krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);

    return st;
}

/*
 * For now, policy objects are expected to be directly under the realm
 * container.
 */
krb5_error_code
krb5_ldap_policydn_to_name(krb5_context context, char *policy_dn, char **name)
{
    int len1, len2;
    krb5_error_code             st = 0;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;

    SETUP_CONTEXT();

    if (ldap_context->lrparams->realmdn == NULL) {
        st = EINVAL;
        goto cleanup;
    }

    len1 = strlen (ldap_context->lrparams->realmdn);
    len2 = strlen (policy_dn);
    if (len1 == 0 || len2 == 0 || len1 > len2) {
        st = EINVAL;
        goto cleanup;
    }

    if (strcmp (ldap_context->lrparams->realmdn, policy_dn + (len2 - len1)) != 0) {
        st = EINVAL;
        goto cleanup;
    }

#if defined HAVE_LDAP_STR2DN
    {
        char *rdn;
        LDAPDN dn;
        rdn = strndup(policy_dn, len2 - len1 - 1); /* 1 character for ',' */

        st = ldap_str2dn(rdn, &dn, LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PEDANTIC);
        free(rdn);
        if (st != 0) {
            st = EINVAL;
            goto cleanup;
        }
        if (dn[0] == NULL || dn[1] != NULL)
            st = EINVAL;
        else if (strcasecmp (dn[0][0]->la_attr.bv_val, "cn") != 0)
            st = EINVAL;
        else {
            *name = strndup(dn[0][0]->la_value.bv_val, dn[0][0]->la_value.bv_len);
            if (*name == NULL)
                st = EINVAL;
        }

        ldap_dnfree(dn);
    }
#elif defined HAVE_LDAP_EXPLODE_DN
    {
        char **parsed_dn;

        /* 1 = return DN components without type prefix */
        parsed_dn = ldap_explode_dn(policy_dn, 1);
        if (parsed_dn == NULL) {
            st = EINVAL;
        } else {
            *name = strdup(parsed_dn[0]);
            if (*name == NULL)
                st = EINVAL;

            ldap_value_free(parsed_dn);
        }
    }
#else
    st = EINVAL;
#endif

cleanup:
    return st;
}

krb5_error_code
krb5_ldap_name_to_policydn(krb5_context context, char *name, char **policy_dn)
{
    int                         len;
    char                        *ptr = NULL;
    krb5_error_code             st = 0;
    kdb5_dal_handle             *dal_handle=NULL;
    krb5_ldap_context           *ldap_context=NULL;

    *policy_dn = NULL;

    /* validate the input parameters */
    if (name == NULL) {
        st = EINVAL;
        goto cleanup;
    }

    /* Used for removing policy reference from an object */
    if (name[0] == '\0') {
        if ((*policy_dn = strdup ("")) == NULL)
            st = ENOMEM;
        goto cleanup;
    }

    SETUP_CONTEXT();

    if (ldap_context->lrparams->realmdn == NULL) {
        st = EINVAL;
        goto cleanup;
    }
    len = strlen (ldap_context->lrparams->realmdn);

    ptr = ldap_filter_correct (name);
    if (ptr == NULL) {
        st = ENOMEM;
        goto cleanup;
    }
    len += strlen (ptr);

    len += sizeof ("cn=") + 3;

    *policy_dn = (char *) malloc (len);
    if (*policy_dn == NULL) {
        st = ENOMEM;
        goto cleanup;
    }

    sprintf (*policy_dn, "cn=%s,%s", ptr, ldap_context->lrparams->realmdn);

cleanup:
    if (ptr != NULL)
        free (ptr);
    return st;
}

/* remove overlapping and repeated subtree entries from the list of subtrees */
static krb5_error_code
remove_overlapping_subtrees(char **listin, char **listop, int *subtcount,
                            int sscope)
{
    int     slen=0, k=0, j=0, lendiff=0;
    int     count = *subtcount;
    char    **subtree = listop;

    slen = count-1;
    for (k=0; k<=slen && listin[k]!=NULL ; k++) {
        for (j=k+1; j<=slen && listin[j]!=NULL ;j++) {
            lendiff = strlen(listin[k]) - strlen(listin[j]);
            if (sscope == 2) {
                if ((lendiff > 0) && (strcasecmp((listin[k])+lendiff, listin[j])==0)) {
                    if (k != slen) {
                        free(listin[k]);
                        listin[k] = listin[slen];
                        listin[slen] = NULL;
                    } else {
                        free(listin[k]);
                        listin[k] = NULL;
                    }
                    slen-=1;
                    k-=1;
                    break;
                } else if ((lendiff < 0) && (strcasecmp((listin[j])+abs(lendiff), listin[k])==0)) {
                    if (j != slen) {
                        free(listin[j]);
                        listin[j] = listin[slen];
                        listin[slen]=NULL;
                    } else {
                        free(listin[j]);
                        listin[j] = NULL;
                    }
                    slen-=1;
                    j-=1;
                }
            }
            if ((lendiff == 0) && (strcasecmp(listin[j], listin[k])==0)) {
                if (j != slen) {
                    free(listin[j]);
                    listin[j] = listin[slen];
                    listin[slen]=NULL;
                } else {
                    free(listin[j]);
                    listin[j] = NULL;
                }
                slen -=1;
                j-=1;
            }
        }
    }
    *subtcount=slen+1;
    for (k=0; k<*subtcount && listin[k]!=NULL; k++) {
        subtree[k] = strdup(listin[k]);
        if (subtree[k] == NULL) {
            return ENOMEM;
        }
    }
    return 0;
}

/*
 * Fill out a krb5_db_entry princ entry struct given a LDAP message containing
 * the results of a principal search of the directory.
 */
krb5_error_code
populate_krb5_db_entry(krb5_context context, krb5_ldap_context *ldap_context,
                       LDAP *ld, LDAPMessage *ent, krb5_const_principal princ,
                       krb5_db_entry *entry)
{
    krb5_error_code st = 0;
    unsigned int    mask = 0;
    int             val;
    krb5_boolean    attr_present = FALSE;
    char            **values = NULL, *policydn = NULL, *pwdpolicydn = NULL;
    char            *polname = NULL, *tktpolname = NULL;
    struct berval   **bvalues = NULL;
    krb5_tl_data    userinfo_tl_data = {0};
    char            **link_references = NULL;
    char *DN = NULL;

    if (princ == NULL) {
        /* XXX WAF probably should just extract princ from ldap result */
        st = EINVAL;
        goto cleanup;
    } else {
        if ((st=krb5_copy_principal(context, princ, &(entry->princ))) != 0)
            goto cleanup;
    }
    /* get the associated directory user information */
    if ((values = ldap_get_values(ld, ent, "krbprincipalname")) != NULL) {
        int i, pcount=0, kerberos_principal_object_type=0;
        char *user;

        if ((st=krb5_unparse_name(context, princ, &user)) != 0)
            goto cleanup;

        for (i=0; values[i] != NULL; ++i) {
            if (strcasecmp(values[i], user) == 0) {
                pcount = ldap_count_values(values);
                break;
            }
        }
        ldap_value_free(values);
        free(user);

        if ((DN = ldap_get_dn(ld, ent)) == NULL) {
            ldap_get_option(ld, LDAP_OPT_RESULT_CODE, &st);
            st = set_ldap_error(context, st, 0);
            goto cleanup;
        }

        if ((values=ldap_get_values(ld, ent, "objectclass")) != NULL) {
            for (i=0; values[i] != NULL; ++i)
                if (strcasecmp(values[i], "krbprincipal") == 0) {
                    kerberos_principal_object_type = KDB_STANDALONE_PRINCIPAL_OBJECT;
                    if ((st=store_tl_data(&userinfo_tl_data, KDB_TL_PRINCTYPE,
                                          &kerberos_principal_object_type)) != 0)
                        goto cleanup;
                    break;
                }
            ldap_value_free(values);
        }

        /* add principalcount, DN and principaltype user information to tl_data */
        if (((st=store_tl_data(&userinfo_tl_data, KDB_TL_PRINCCOUNT, &pcount)) != 0) ||
            ((st=store_tl_data(&userinfo_tl_data, KDB_TL_USERDN, DN)) != 0))
            goto cleanup;
    }

    /* read all the kerberos attributes */

    /* KRBLASTSUCCESSFULAUTH */
    if ((st=krb5_ldap_get_time(ld, ent, "krbLastSuccessfulAuth",
                               &(entry->last_success), &attr_present)) != 0)
        goto cleanup;
    if (attr_present == TRUE)
        mask |= KDB_LAST_SUCCESS_ATTR;

    /* KRBLASTFAILEDAUTH */
    if ((st=krb5_ldap_get_time(ld, ent, "krbLastFailedAuth",
                               &(entry->last_failed), &attr_present)) != 0)
        goto cleanup;
    if (attr_present == TRUE)
        mask |= KDB_LAST_FAILED_ATTR;

    /* KRBLOGINFAILEDCOUNT */
    if (krb5_ldap_get_value(ld, ent, "krbLoginFailedCount", &val) == 0) {
        entry->fail_auth_count = val;
        mask |= KDB_FAIL_AUTH_COUNT_ATTR;
    }

    /* KRBMAXTICKETLIFE */
    if (krb5_ldap_get_value(ld, ent, "krbmaxticketlife", &(entry->max_life)) == 0)
        mask |= KDB_MAX_LIFE_ATTR;

    /* KRBMAXRENEWABLEAGE */
    if (krb5_ldap_get_value(ld, ent, "krbmaxrenewableage",
                            &(entry->max_renewable_life)) == 0)
        mask |= KDB_MAX_RLIFE_ATTR;

    /* KRBTICKETFLAGS */
    if (krb5_ldap_get_value(ld, ent, "krbticketflags", &(entry->attributes)) == 0)
        mask |= KDB_TKT_FLAGS_ATTR;

    /* PRINCIPAL EXPIRATION TIME */
    if ((st=krb5_ldap_get_time(ld, ent, "krbprincipalexpiration", &(entry->expiration),
                               &attr_present)) != 0)
        goto cleanup;
    if (attr_present == TRUE)
        mask |= KDB_PRINC_EXPIRE_TIME_ATTR;

    /* PASSWORD EXPIRATION TIME */
    if ((st=krb5_ldap_get_time(ld, ent, "krbpasswordexpiration", &(entry->pw_expiration),
                               &attr_present)) != 0)
        goto cleanup;
    if (attr_present == TRUE)
        mask |= KDB_PWD_EXPIRE_TIME_ATTR;

    /* KRBPOLICYREFERENCE */

    if ((st=krb5_ldap_get_string(ld, ent, "krbticketpolicyreference", &policydn,
                                 &attr_present)) != 0)
        goto cleanup;
    if (attr_present == TRUE) {
        mask |= KDB_POL_REF_ATTR;
        /* Ensure that the policy is inside the realm container */
        if ((st = krb5_ldap_policydn_to_name (context, policydn, &tktpolname)) != 0)
            goto cleanup;
    }

    /* KRBPWDPOLICYREFERENCE */
    if ((st=krb5_ldap_get_string(ld, ent, "krbpwdpolicyreference", &pwdpolicydn,
                                 &attr_present)) != 0)
        goto cleanup;
    if (attr_present == TRUE) {
        mask |= KDB_PWD_POL_REF_ATTR;

        /* Ensure that the policy is inside the realm container */
        if ((st = krb5_ldap_policydn_to_name (context, pwdpolicydn, &polname)) != 0)
            goto cleanup;

        if ((st = krb5_update_tl_kadm_data(context, entry, polname)) != 0)
            goto cleanup;
    }

    /* KRBSECRETKEY */
    if ((bvalues=ldap_get_values_len(ld, ent, "krbprincipalkey")) != NULL) {
        krb5_kvno mkvno = 0;

        mask |= KDB_SECRET_KEY_ATTR;
        if ((st=krb5_decode_krbsecretkey(context, entry, bvalues, &userinfo_tl_data, &mkvno)) != 0)
            goto cleanup;
        if (mkvno != 0) {
            /* don't add the tl data if mkvno == 0 */
            if ((st=krb5_dbe_update_mkvno(context, entry, mkvno)) != 0)
                goto cleanup;
        }
    }

    /* LAST PASSWORD CHANGE */
    {
        krb5_timestamp lstpwdchng=0;
        if ((st=krb5_ldap_get_time(ld, ent, "krbLastPwdChange",
                                   &lstpwdchng, &attr_present)) != 0)
            goto cleanup;
        if (attr_present == TRUE) {
            if ((st=krb5_dbe_update_last_pwd_change(context, entry,
                                                    lstpwdchng)))
                goto cleanup;
            mask |= KDB_LAST_PWD_CHANGE_ATTR;
        }
    }

    /* LAST ADMIN UNLOCK */
    {
        krb5_timestamp unlock_time=0;
        if ((st=krb5_ldap_get_time(ld, ent, "krbLastAdminUnlock",
                                   &unlock_time, &attr_present)) != 0)
            goto cleanup;
        if (attr_present == TRUE) {
            if ((st=krb5_dbe_update_last_admin_unlock(context, entry,
                                                      unlock_time)))
                goto cleanup;
            mask |= KDB_LAST_ADMIN_UNLOCK_ATTR;
        }
    }

    /* ALLOWED TO DELEGATE TO */
    {
        char **a2d2 = NULL;
        int i;
        krb5_tl_data **tlp;

        st = krb5_ldap_get_strings(ld, ent, "krbAllowedToDelegateTo",
                                   &a2d2, &attr_present);
        if (st != 0)
            goto cleanup;

        if (attr_present == TRUE) {
            for (tlp = &entry->tl_data; *tlp; tlp = &(*tlp)->tl_data_next)
                ;
            for (i = 0; a2d2[i] != NULL; i++) {
                krb5_tl_data *tl = k5alloc(sizeof(*tl), &st);
                if (st != 0) {
                    ldap_value_free(a2d2);
                    goto cleanup;
                }
                tl->tl_data_type = KRB5_TL_CONSTRAINED_DELEGATION_ACL;
                tl->tl_data_length = strlen(a2d2[i]);
                tl->tl_data_contents = (krb5_octet *)strdup(a2d2[i]);
                if (tl->tl_data_contents == NULL) {
                    st = ENOMEM;
                    ldap_value_free(a2d2);
                    free(tl);
                    goto cleanup;
                }
                tl->tl_data_next = NULL;
                *tlp = tl;
                tlp = &tl->tl_data_next;
            }
            ldap_value_free(a2d2);
        }
    }

    /* KRBOBJECTREFERENCES */
    {
        int i=0;

        if ((st = krb5_ldap_get_strings(ld, ent, "krbobjectreferences",
                                        &link_references, &attr_present)) != 0)
            goto cleanup;
        if (link_references != NULL) {
            for (i=0; link_references[i] != NULL; ++i) {
                if ((st = store_tl_data(&userinfo_tl_data, KDB_TL_LINKDN,
                                        link_references[i])) != 0)
                    goto cleanup;
            }
        }
    }

    /* Set tl_data */
    {
        int i;
        struct berval **ber_tl_data = NULL;
        krb5_tl_data *ptr = NULL;

        if ((ber_tl_data = ldap_get_values_len (ld, ent, "krbExtraData")) != NULL) {
            for (i = 0; ber_tl_data[i] != NULL; i++) {
                if ((st = berval2tl_data (ber_tl_data[i] , &ptr)) != 0)
                    break;
                st = krb5_dbe_update_tl_data(context, entry, ptr);
                free(ptr->tl_data_contents);
                free(ptr);
                if (st != 0)
                    break;
            }
            ldap_value_free_len (ber_tl_data);
            if (st != 0)
                goto cleanup;
            mask |= KDB_EXTRA_DATA_ATTR;
        }
    }

    /* update the mask of attributes present on the directory object to the tl_data */
    if ((st=store_tl_data(&userinfo_tl_data, KDB_TL_MASK, &mask)) != 0)
        goto cleanup;
    if ((st=krb5_dbe_update_tl_data(context, entry, &userinfo_tl_data)) != 0)
        goto cleanup;

    if ((st=krb5_read_tkt_policy (context, ldap_context, entry, tktpolname)) !=0)
        goto cleanup;

    /* XXX so krb5_encode_princ_contents() will be happy */
    entry->len = KRB5_KDB_V1_BASE_LENGTH;

cleanup:

    if (DN != NULL)
        ldap_memfree(DN);

    if (userinfo_tl_data.tl_data_contents != NULL)
        free(userinfo_tl_data.tl_data_contents);

    if (pwdpolicydn != NULL)
        free(pwdpolicydn);

    if (polname != NULL)
        free(polname);

    if (tktpolname != NULL)
        free (tktpolname);

    if (policydn != NULL)
        free(policydn);

    if (link_references) {
        int i;
        for (i=0; link_references[i] != NULL; ++i)
            free (link_references[i]);
        free (link_references);
    }

    return (st);
}

/*
 * Solaris libldap does not provide the following functions which are in
 * OpenLDAP.
 */
#ifndef HAVE_LDAP_INITIALIZE
int
ldap_initialize(LDAP **ldp, char *url)
{
    int rc = 0;
    LDAP *ld = NULL;
    LDAPURLDesc *ludp = NULL;

    /* For now, we don't use any DN that may be provided.  And on
       Solaris (based on Mozilla's LDAP client code), we need the
       _nodn form to parse "ldap://host" without a trailing slash.

       Also, this version won't handle an input string which contains
       multiple URLs, unlike the OpenLDAP ldap_initialize.  See
       https://bugzilla.mozilla.org/show_bug.cgi?id=353336#c1 .  */
#ifdef HAVE_LDAP_URL_PARSE_NODN
    rc = ldap_url_parse_nodn(url, &ludp);
#else
    rc = ldap_url_parse(url, &ludp);
#endif
    if (rc == 0) {

        ld = ldap_init(ludp->lud_host, ludp->lud_port);
        if (ld != NULL) {
            *ldp = ld;
#if 0
            printf("lud_host %s lud_port %d\n", ludp->lud_host,
                   ludp->lud_port);
#endif
        }
        else
            rc = KRB5_KDB_ACCESS_ERROR;

        ldap_free_urldesc(ludp);
    }
    return rc;
}
#endif /* HAVE_LDAP_INITIALIZE */

#ifndef HAVE_LDAP_UNBIND_EXT_S
int
ldap_unbind_ext_s(LDAP *ld, LDAPControl **sctrls, LDAPControl **cctrls)
{
    return ldap_unbind_ext(ld, sctrls, cctrls);
}
#endif /* HAVE_LDAP_UNBIND_EXT_S */

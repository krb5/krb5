/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Source$
 */

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <k5-int.h>
#include <kdb.h>
#include <kadm5/admin.h>
#include <adm_proto.h>

#include "fake-addrinfo.h"


#include <krb5.h>
#include <kdb.h>
#include "kdb5_util.h"

static int add_admin_princ(void *handle, krb5_context context,
                           char *name, char *realm, int attrs, int lifetime);
static int add_admin_princs(void *handle, krb5_context context, char *realm);

#define ERR 1
#define OK 0

#define ADMIN_LIFETIME 60*60*3 /* 3 hours */
#define CHANGEPW_LIFETIME 60*5 /* 5 minutes */

/*
 * Function: kadm5_create
 *
 * Purpose: create admin principals in KDC database
 *
 * Arguments:   params  (r) configuration parameters to use
 *
 * Effects:  Creates KADM5_ADMIN_SERVICE and KADM5_CHANGEPW_SERVICE
 * principals in the KDC database and sets their attributes
 * appropriately.
 */
int kadm5_create(kadm5_config_params *params)
{
    int retval;
    krb5_context context;

    kadm5_config_params lparams;

    if ((retval = kadm5_init_krb5_context(&context)))
        exit(ERR);

    /*
     * The lock file has to exist before calling kadm5_init, but
     * params->admin_lockfile may not be set yet...
     */
    if ((retval = kadm5_get_config_params(context, 1,
                                          params, &lparams))) {
        com_err(progname, retval, _("while looking up the Kerberos "
                                    "configuration"));
        return 1;
    }

    retval = kadm5_create_magic_princs(&lparams, context);

    kadm5_free_config_params(context, &lparams);
    krb5_free_context(context);

    return retval;
}

int kadm5_create_magic_princs(kadm5_config_params *params,
                              krb5_context context)
{
    int retval;
    void *handle;

    retval = krb5_klog_init(context, "admin_server", progname, 0);
    if (retval)
        return retval;
    if ((retval = kadm5_init(context, progname, NULL, NULL, params,
                             KADM5_STRUCT_VERSION,
                             KADM5_API_VERSION_4,
                             db5util_db_args,
                             &handle))) {
        com_err(progname, retval, _("while initializing the Kerberos admin "
                                    "interface"));
        return retval;
    }

    retval = add_admin_princs(handle, context, params->realm);

    kadm5_destroy(handle);

    krb5_klog_close(context);

    return retval;
}

/*
 * Function: build_name_with_realm
 *
 * Purpose: concatenate a name and a realm to form a krb5 name
 *
 * Arguments:
 *
 *      name    (input) the name
 *      realm   (input) the realm
 *
 * Returns:
 *
 *      pointer to name@realm, in allocated memory, or NULL if it
 *      cannot be allocated
 *
 * Requires: both strings are null-terminated
 */
static char *build_name_with_realm(char *name, char *realm)
{
    char *n;

    asprintf(&n, "%s@%s", name, realm);
    return n;
}

/*
 * Function: add_admin_princs
 *
 * Purpose: create admin principals
 *
 * Arguments:
 *
 *      rseed           (input) random seed
 *      realm           (input) realm, or NULL for default realm
 *      <return value>  (output) status, 0 for success, 1 for serious error
 *
 * Requires:
 *
 * Effects:
 *
 * add_admin_princs creates KADM5_ADMIN_SERVICE,
 * KADM5_CHANGEPW_SERVICE.  If any of these exist a message is
 * printed.  If any of these existing principal do not have the proper
 * attributes, a warning message is printed.
 */
static int add_admin_princs(void *handle, krb5_context context, char *realm)
{
    krb5_error_code ret = 0;
    char *service_name = 0, *p;
    char localname[MAXHOSTNAMELEN];
    struct addrinfo *ai, ai_hints;
    int gai_error;

    if (gethostname(localname, MAXHOSTNAMELEN)) {
        ret = errno;
        perror("gethostname");
        goto clean_and_exit;
    }
    memset(&ai_hints, 0, sizeof(ai_hints));
    ai_hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;
    gai_error = getaddrinfo(localname, (char *)NULL, &ai_hints, &ai);
    if (gai_error) {
        ret = EINVAL;
        fprintf(stderr, "getaddrinfo(%s): %s\n", localname,
                gai_strerror(gai_error));
        goto clean_and_exit;
    }
    if (ai->ai_canonname == NULL) {
        ret = EINVAL;
        fprintf(stderr, _("getaddrinfo(%s): Cannot determine canonical "
                          "hostname.\n"), localname);
        freeaddrinfo(ai);
        goto clean_and_exit;
    }
    for (p = ai->ai_canonname; *p; p++) {
#ifdef isascii
        if (!isascii(*p))
            continue;
#else
        if (*p < ' ')
            continue;
        if (*p > '~')
            continue;
#endif
        if (!isupper(*p))
            continue;
        *p = tolower(*p);
    }
    if (asprintf(&service_name, "kadmin/%s", ai->ai_canonname) < 0) {
        ret = ENOMEM;
        fprintf(stderr, _("Out of memory\n"));
        freeaddrinfo(ai);
        goto clean_and_exit;
    }
    freeaddrinfo(ai);

    if ((ret = add_admin_princ(handle, context,
                               service_name, realm,
                               KRB5_KDB_DISALLOW_TGT_BASED,
                               ADMIN_LIFETIME)))
        goto clean_and_exit;

    if ((ret = add_admin_princ(handle, context,
                               KADM5_ADMIN_SERVICE, realm,
                               KRB5_KDB_DISALLOW_TGT_BASED,
                               ADMIN_LIFETIME)))
        goto clean_and_exit;

    if ((ret = add_admin_princ(handle, context,
                               KADM5_CHANGEPW_SERVICE, realm,
                               KRB5_KDB_DISALLOW_TGT_BASED |
                               KRB5_KDB_PWCHANGE_SERVICE,
                               CHANGEPW_LIFETIME)))
        goto clean_and_exit;

clean_and_exit:
    free(service_name);

    return ret;
}

/*
 * Function: add_admin_princ
 *
 * Arguments:
 *
 *      creator         (r) principal to use as "mod_by"
 *      rseed           (r) seed for random key generator
 *      name            (r) principal name
 *      realm           (r) realm name for principal
 *      attrs           (r) principal's attributes
 *      lifetime        (r) principal's max life, or 0
 *      not_unique      (r) error message for multiple entries, never used
 *      exists          (r) warning message for principal exists
 *      wrong_attrs     (r) warning message for wrong attributes
 *
 * Returns:
 *
 *      OK on success
 *      ERR on serious errors
 *
 * Effects:
 *
 * If the principal is not unique, not_unique is printed (but this
 * never happens).  If the principal exists, then exists is printed
 * and if the principals attributes != attrs, wrong_attrs is printed.
 * Otherwise, the principal is created with mod_by creator and
 * attributes attrs and max life of lifetime (if not zero).
 */

int add_admin_princ(void *handle, krb5_context context,
                    char *name, char *realm, int attrs, int lifetime)
{
    char *fullname;
    krb5_error_code ret;
    kadm5_principal_ent_rec ent;

    memset(&ent, 0, sizeof(ent));

    fullname = build_name_with_realm(name, realm);
    ret = krb5_parse_name(context, fullname, &ent.principal);
    if (ret) {
        com_err(progname, ret, _("while parsing admin principal name"));
        return(ERR);
    }
    ent.max_life = lifetime;
    ent.attributes = attrs | KRB5_KDB_DISALLOW_ALL_TIX;

    ret = kadm5_create_principal(handle, &ent,
                                 (KADM5_PRINCIPAL | KADM5_MAX_LIFE |
                                  KADM5_ATTRIBUTES),
                                 "to-be-random");
    if (ret) {
        if (ret != KADM5_DUP) {
            com_err(progname, ret, _("while creating principal %s"), fullname);
            krb5_free_principal(context, ent.principal);
            free(fullname);
            return ERR;
        }
    } else {
        /* only randomize key if we created the principal */
        ret = kadm5_randkey_principal(handle, ent.principal, NULL, NULL);
        if (ret) {
            com_err(progname, ret, _("while randomizing principal %s"),
                    fullname);
            krb5_free_principal(context, ent.principal);
            free(fullname);
            return ERR;
        }

        ent.attributes = attrs;
        ret = kadm5_modify_principal(handle, &ent, KADM5_ATTRIBUTES);
        if (ret) {
            com_err(progname, ret, _("while setting attributes on %s"),
                    fullname);
            krb5_free_principal(context, ent.principal);
            free(fullname);
            return ERR;
        }
    }

    krb5_free_principal(context, ent.principal);
    free(fullname);

    return OK;
}

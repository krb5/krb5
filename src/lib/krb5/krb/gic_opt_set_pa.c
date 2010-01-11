/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 1995, 2003, 2008 by the Massachusetts Institute of Technology.  All
 * Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * krb5_get_init_creds_opt_set_pa()
 * krb5_preauth_supply_preauth_data()
 */

#include "k5-int.h"
#include "int-proto.h"

static krb5_error_code
add_gic_opt_ext_preauth_data(krb5_context context,
                             krb5_gic_opt_ext *opte,
                             const char *attr,
                             const char *value)
{
    size_t newsize;
    int i;
    krb5_gic_opt_pa_data *newpad;

    newsize = opte->opt_private->num_preauth_data + 1;
    newsize = newsize * sizeof(*opte->opt_private->preauth_data);
    if (opte->opt_private->preauth_data == NULL)
        newpad = malloc(newsize);
    else
        newpad = realloc(opte->opt_private->preauth_data, newsize);
    if (newpad == NULL)
        return ENOMEM;
    opte->opt_private->preauth_data = newpad;

    i = opte->opt_private->num_preauth_data;
    newpad[i].attr = strdup(attr);
    if (newpad[i].attr == NULL)
        return ENOMEM;
    newpad[i].value = strdup(value);
    if (newpad[i].value == NULL) {
        free(newpad[i].attr);
        return ENOMEM;
    }
    opte->opt_private->num_preauth_data += 1;
    return 0;
}

/*
 * This function allows the caller to supply options to preauth
 * plugins.  Preauth plugin modules are given a chance to look
 * at each option at the time this function is called in ordre
 * to check the validity of the option.
 * The 'opt' pointer supplied to this function must have been
 * obtained using krb5_get_init_creds_opt_alloc()
 */
krb5_error_code KRB5_CALLCONV
krb5_get_init_creds_opt_set_pa(krb5_context context,
                               krb5_get_init_creds_opt *opt,
                               const char *attr,
                               const char *value)
{
    krb5_error_code retval;
    krb5_gic_opt_ext *opte;

    retval = krb5int_gic_opt_to_opte(context, opt, &opte, 0,
                                     "krb5_get_init_creds_opt_set_pa");
    if (retval)
        return retval;

    /*
     * Copy the option into the extended get_init_creds_opt structure
     */
    retval = add_gic_opt_ext_preauth_data(context, opte, attr, value);
    if (retval)
        return retval;

    /*
     * Give the plugins a chance to look at the option now.
     */
    retval = krb5_preauth_supply_preauth_data(context, opte, attr, value);
    return retval;
}

/*
 * Give all the preauth plugins a look at the preauth option which
 * has just been set
 */
krb5_error_code
krb5_preauth_supply_preauth_data(krb5_context context,
                                 krb5_gic_opt_ext *opte,
                                 const char *attr,
                                 const char *value)
{
    krb5_error_code retval = 0;
    int i;
    void *pctx;
    const char *emsg = NULL;

    if (context->preauth_context == NULL)
        krb5_init_preauth_context(context);
    if (context->preauth_context == NULL) {
        retval = EINVAL;
        krb5int_set_error(&context->err, retval,
                          "krb5_preauth_supply_preauth_data: "
                          "Unable to initialize preauth context");
        return retval;
    }

    /*
     * Go down the list of preauth modules, and supply them with the
     * attribute/value pair.
     */
    for (i = 0; i < context->preauth_context->n_modules; i++) {
        if (context->preauth_context->modules[i].client_supply_gic_opts == NULL)
            continue;
        pctx = context->preauth_context->modules[i].plugin_context;
        retval = (*context->preauth_context->modules[i].client_supply_gic_opts)
            (context, pctx,
             (krb5_get_init_creds_opt *)opte, attr, value);
        if (retval) {
            emsg = krb5_get_error_message(context, retval);
            krb5int_set_error(&context->err, retval, "Preauth plugin %s: %s",
                              context->preauth_context->modules[i].name, emsg);
            krb5_free_error_message(context, emsg);
            break;
        }
    }
    return retval;
}

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/kadm5/srv/pwqual.c
 *
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 *
 * Consumer interface for password quality plugins
 */

#include "k5-int.h"
#include "server_internal.h"
#include <krb5/pwqual_plugin.h>

struct pwqual_handle_st {
    struct krb5_pwqual_vtable_st vt;
    krb5_pwqual_moddata data;
};

krb5_error_code
k5_pwqual_load(krb5_context context, pwqual_handle **handles)
{
    krb5_error_code ret;
    krb5_plugin_init_fn *modules = NULL, *mod;
    size_t count;
    pwqual_handle *list = NULL, handle = NULL;

    ret = k5_plugin_load_all(context, PLUGIN_INTERFACE_PWQUAL, &modules);
    if (ret != 0)
	goto cleanup;

    /* Allocate a large enough list of handles. */
    for (count = 0; modules[count] != NULL; count++);
    list = k5alloc((count + 1) * sizeof(*list), &ret);
    if (list == NULL)
	goto cleanup;

    /* For each module, allocate a handle and initialize its vtable.  Skip
     * modules which don't successfully initialize. */
    count = 0;
    for (mod = modules; *mod != NULL; mod++) {
	handle = k5alloc(sizeof(*handle), &ret);
	if (handle == NULL)
	    goto cleanup;
	ret = (*mod)(context, 1, 1, (krb5_plugin_vtable)&handle->vt);
	if (ret == 0)
	    list[count++] = handle;
	else
	    free(handle);
    }

    *handles = list;
    list = NULL;

cleanup:
    k5_plugin_free_modules(context, modules);
    k5_pwqual_free_handles(context, list);
    return ret;
}

krb5_error_code
k5_pwqual_free_handles(krb5_context context, pwqual_handle *handles)
{
    /* It's the caller's responsibility to close each handle, so all of the
     * module data should be freed by now, leaving only the list itself. */
    free(handles);
}

krb5_error_code
k5_pwqual_open(krb5_context context, pwqual_handle handle,
               const char *dict_file)
{
    if (handle->data != NULL)
	return EINVAL;
    if (handle->vt.open == NULL)
        return 0;
    return handle->vt.open(context, dict_file, &handle->data);
}

krb5_error_code
k5_pwqual_check(krb5_context context, pwqual_handle handle,
		const char *password, kadm5_policy_ent_t policy,
		krb5_principal princ)
{
    return handle->vt.check(context, handle->data, password, policy, princ);
}

void
k5_pwqual_close(krb5_context context, pwqual_handle handle)
{
    if (handle->vt.close)
        handle->vt.close(context, handle->data);
    handle->data = NULL;
}

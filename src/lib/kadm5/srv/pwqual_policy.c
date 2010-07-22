/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/kadm5/srv/pwqual_policy.c
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
 * Password quality module to enforce password policy
 */

#include "k5-platform.h"
#include <krb5/pwqual_plugin.h>
#include <kadm5/admin.h>
#include <ctype.h>
#include "server_internal.h"

/* Implement the password quality check module. */
static krb5_error_code
policy_check(krb5_context context, krb5_pwqual_moddata data,
	     const char *password, kadm5_policy_ent_t policy,
	     krb5_principal princ)
{
    int nupper = 0, nlower = 0, ndigit = 0, npunct = 0, nspec = 0;
    const char *s;
    unsigned char c;

    if (policy == NULL)
	return (*password == '\0') ? KADM5_PASS_Q_TOOSHORT : 0;

    if(strlen(password) < (size_t)policy->pw_min_length)
	return KADM5_PASS_Q_TOOSHORT;
    s = password;
    while ((c = (unsigned char)*s++)) {
	if (islower(c))
	    nlower = 1;
	else if (isupper(c))
	    nupper = 1;
	else if (isdigit(c))
	    ndigit = 1;
	else if (ispunct(c))
	    npunct = 1;
	else
	    nspec = 1;
    }
    if ((nupper + nlower + ndigit + npunct + nspec) < policy->pw_min_classes)
	return KADM5_PASS_Q_CLASS;
    return 0;
}

krb5_error_code
pwqual_policy_init(krb5_context context, int maj_ver, int min_ver,
		   krb5_plugin_vtable vtable)
{
    krb5_pwqual_vtable vt;

    if (maj_ver != 1)
        return EINVAL; /* XXX create error code */
    vt = (krb5_pwqual_vtable)vtable;
    vt->check = policy_check;
    return 0;
}

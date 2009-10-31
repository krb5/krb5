/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/os/ktdefname.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * Return default keytab file name.
 */

#define NEED_WINDOWS

#include "k5-int.h"

extern char *krb5_defkeyname;

/* this is a an exceedinly gross thing. */
char *krb5_overridekeyname = NULL;

krb5_error_code KRB5_CALLCONV
krb5_kt_default_name(krb5_context context, char *name, int name_size)
{
    char *cp = 0;
    char *retval;
    unsigned int namesize = (name_size < 0 ? 0 : name_size);

    if (krb5_overridekeyname) {
        if (strlcpy(name, krb5_overridekeyname, namesize) >= namesize)
            return KRB5_CONFIG_NOTENUFSPACE;
    } else if ((context->profile_secure == FALSE) &&
               (cp = getenv("KRB5_KTNAME"))) {
        if (strlcpy(name, cp, namesize) >= namesize)
            return KRB5_CONFIG_NOTENUFSPACE;
    } else if ((profile_get_string(context->profile,
                                   KRB5_CONF_LIBDEFAULTS,
                                   KRB5_CONF_DEFAULT_KEYTAB_NAME, NULL,
                                   NULL, &retval) == 0) &&
               retval) {
        if (strlcpy(name, retval, namesize) >= namesize)
            return KRB5_CONFIG_NOTENUFSPACE;
        profile_release_string(retval);
    } else {
#if defined(_WIN32)
        {
            char    defname[160];
            int     len;

            len= GetWindowsDirectory( defname, sizeof(defname)-2 );
            defname[len]= '\0';
            if ( (len + strlen(krb5_defkeyname) + 1) > namesize )
                return KRB5_CONFIG_NOTENUFSPACE;
            snprintf(name, namesize, krb5_defkeyname, defname);
        }
#else
        if (strlcpy(name, krb5_defkeyname, namesize) >= namesize)
            return KRB5_CONFIG_NOTENUFSPACE;
#endif
    }
    return 0;
}

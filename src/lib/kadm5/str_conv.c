/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/kadm5/str_conv.c */
/*
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 */

/* Convert between strings and Kerberos internal data. */

/*
 * Table of contents:
 *
 * String decoding:
 * ----------------
 * krb5_string_to_flags()       - Convert string to krb5_flags.
 *
 * String encoding:
 * ----------------
 * krb5_flags_to_string()       - Convert krb5_flags to string.
 */

#include "k5-int.h"
#include "admin_internal.h"
#include "adm_proto.h"

/*
 * Local data structures.
 */
struct flags_lookup_entry {
    krb5_flags          fl_flags;               /* Flag                 */
    krb5_boolean        fl_sense;               /* Sense of the flag    */
    const char *        fl_specifier;           /* How to recognize it  */
    const char *        fl_output;              /* How to spit it out   */
};

/*
 * Local strings
 */

static const char default_tupleseps[]   = ", \t";
static const char default_ksaltseps[]   = ":";

/* Keytype strings */
/* Flags strings */
static const char flags_pdate_in[]      = "postdateable";
static const char flags_fwd_in[]        = "forwardable";
static const char flags_tgtbased_in[]   = "tgt-based";
static const char flags_renew_in[]      = "renewable";
static const char flags_proxy_in[]      = "proxiable";
static const char flags_dup_skey_in[]   = "dup-skey";
static const char flags_tickets_in[]    = "allow-tickets";
static const char flags_preauth_in[]    = "preauth";
static const char flags_hwauth_in[]     = "hwauth";
static const char flags_ok_as_delegate_in[]     = "ok-as-delegate";
static const char flags_pwchange_in[]   = "pwchange";
static const char flags_service_in[]    = "service";
static const char flags_pwsvc_in[]      = "pwservice";
static const char flags_md5_in[]        = "md5";
static const char flags_ok_to_auth_as_delegate_in[] = "ok-to-auth-as-delegate";
static const char flags_no_auth_data_required_in[] = "no-auth-data-required";
static const char flags_pdate_out[]     = N_("Not Postdateable");
static const char flags_fwd_out[]       = N_("Not Forwardable");
static const char flags_tgtbased_out[]  = N_("No TGT-based requests");
static const char flags_renew_out[]     = N_("Not renewable");
static const char flags_proxy_out[]     = N_("Not proxiable");
static const char flags_dup_skey_out[]  = N_("No DUP_SKEY requests");
static const char flags_tickets_out[]   = N_("All Tickets Disallowed");
static const char flags_preauth_out[]   = N_("Preauthentication required");
static const char flags_hwauth_out[]    = N_("HW authentication required");
static const char flags_ok_as_delegate_out[]    = N_("OK as Delegate");
static const char flags_pwchange_out[]  = N_("Password Change required");
static const char flags_service_out[]   = N_("Service Disabled");
static const char flags_pwsvc_out[]     = N_("Password Changing Service");
static const char flags_md5_out[]       = N_("RSA-MD5 supported");
static const char flags_ok_to_auth_as_delegate_out[] = N_("Protocol transition with delegation allowed");
static const char flags_no_auth_data_required_out[] = N_("No authorization data required");
static const char flags_default_neg[]   = "-";
static const char flags_default_sep[]   = " ";

/*
 * Lookup tables.
 */

static const struct flags_lookup_entry flags_table[] = {
/* flag                         sense   input specifier    output string     */
/*----------------------------- ------- ------------------ ------------------*/
    { KRB5_KDB_DISALLOW_POSTDATED,  0,      flags_pdate_in,    flags_pdate_out   },
    { KRB5_KDB_DISALLOW_FORWARDABLE,0,      flags_fwd_in,      flags_fwd_out     },
    { KRB5_KDB_DISALLOW_TGT_BASED,  0,      flags_tgtbased_in, flags_tgtbased_out},
    { KRB5_KDB_DISALLOW_RENEWABLE,  0,      flags_renew_in,    flags_renew_out   },
    { KRB5_KDB_DISALLOW_PROXIABLE,  0,      flags_proxy_in,    flags_proxy_out   },
    { KRB5_KDB_DISALLOW_DUP_SKEY,   0,      flags_dup_skey_in, flags_dup_skey_out},
    { KRB5_KDB_DISALLOW_ALL_TIX,    0,      flags_tickets_in,  flags_tickets_out },
    { KRB5_KDB_REQUIRES_PRE_AUTH,   1,      flags_preauth_in,  flags_preauth_out },
    { KRB5_KDB_REQUIRES_HW_AUTH,    1,      flags_hwauth_in,   flags_hwauth_out  },
    { KRB5_KDB_OK_AS_DELEGATE,      1,      flags_ok_as_delegate_in, flags_ok_as_delegate_out },
    { KRB5_KDB_REQUIRES_PWCHANGE,   1,      flags_pwchange_in, flags_pwchange_out},
    { KRB5_KDB_DISALLOW_SVR,        0,      flags_service_in,  flags_service_out },
    { KRB5_KDB_PWCHANGE_SERVICE,    1,      flags_pwsvc_in,    flags_pwsvc_out   },
    { KRB5_KDB_SUPPORT_DESMD5,      1,      flags_md5_in,      flags_md5_out     },
    { KRB5_KDB_OK_TO_AUTH_AS_DELEGATE,  1,  flags_ok_to_auth_as_delegate_in, flags_ok_to_auth_as_delegate_out },
    { KRB5_KDB_NO_AUTH_DATA_REQUIRED,   1,  flags_no_auth_data_required_in, flags_no_auth_data_required_out }
};
static const int flags_table_nents = sizeof(flags_table)/
    sizeof(flags_table[0]);


krb5_error_code
krb5_string_to_flags(string, positive, negative, flagsp)
    char        * string;
    const char  * positive;
    const char  * negative;
    krb5_flags  * flagsp;
{
    int         i;
    int         found;
    const char  *neg;
    size_t      nsize, psize;
    int         cpos;
    int         sense;

    found = 0;
    /* We need to have a way to negate it. */
    neg = (negative) ? negative : flags_default_neg;
    nsize = strlen(neg);
    psize = (positive) ? strlen(positive) : 0;

    cpos = 0;
    sense = 1;
    /* First check for positive or negative sense */
    if (!strncasecmp(neg, string, nsize)) {
        sense = 0;
        cpos += (int) nsize;
    }
    else if (psize && !strncasecmp(positive, string, psize)) {
        cpos += (int) psize;
    }

    for (i=0; i<flags_table_nents; i++) {
        if (!strcasecmp(&string[cpos], flags_table[i].fl_specifier)) {
            found = 1;
            if (sense == (int) flags_table[i].fl_sense)
                *flagsp |= flags_table[i].fl_flags;
            else
                *flagsp &= ~flags_table[i].fl_flags;

            break;
        }
    }
    return((found) ? 0 : EINVAL);
}

krb5_error_code
krb5_flags_to_string(flags, sep, buffer, buflen)
    krb5_flags  flags;
    const char  * sep;
    char        * buffer;
    size_t      buflen;
{
    int                 i;
    krb5_flags          pflags;
    const char          *sepstring;
    struct k5buf        buf;

    pflags = 0;
    sepstring = (sep) ? sep : flags_default_sep;
    k5_buf_init_fixed(&buf, buffer, buflen);
    /* Blast through the table matching all we can */
    for (i=0; i<flags_table_nents; i++) {
        if (flags & flags_table[i].fl_flags) {
            if (buf.len > 0)
                k5_buf_add(&buf, sepstring);
            k5_buf_add(&buf, _(flags_table[i].fl_output));
            /* Keep track of what we matched */
            pflags |= flags_table[i].fl_flags;
        }
    }
    if (k5_buf_status(&buf) != 0)
        return(ENOMEM);

    /* See if there's any leftovers */
    if (flags & ~pflags)
        return(EINVAL);

    return(0);
}

krb5_error_code
krb5_input_flag_to_string(flag, buffer, buflen)
    int         flag;
    char        * buffer;
    size_t      buflen;
{
    if(flag < 0 || flag >= flags_table_nents) return ENOENT; /* End of list */
    if(strlcpy(buffer, flags_table[flag].fl_specifier, buflen) >= buflen)
        return ENOMEM;
    return  0;
}

/*
 * krb5_keysalt_is_present()    - Determine if a key/salt pair is present
 *                                in a list of key/salt tuples.
 *
 *      Salttype may be negative to indicate a search for only a enctype.
 */
krb5_boolean
krb5_keysalt_is_present(ksaltlist, nksalts, enctype, salttype)
    krb5_key_salt_tuple *ksaltlist;
    krb5_int32          nksalts;
    krb5_enctype        enctype;
    krb5_int32          salttype;
{
    krb5_boolean        foundit;
    int                 i;

    foundit = 0;
    if (ksaltlist) {
        for (i=0; i<nksalts; i++) {
            if ((ksaltlist[i].ks_enctype == enctype) &&
                ((ksaltlist[i].ks_salttype == salttype) ||
                 (salttype < 0))) {
                foundit = 1;
                break;
            }
        }
    }
    return(foundit);
}

/* NOTE: This is a destructive parser (writes NULs). */
static krb5_error_code
string_to_keysalt(char *s, const char *ksaltseps,
                  krb5_enctype *etype, krb5_int32 *stype)
{
    char *sp;
    const char *ksseps = (ksaltseps != NULL) ? ksaltseps : default_ksaltseps;
    krb5_error_code ret = 0;

    sp = strpbrk(s, ksseps);
    if (sp != NULL) {
        *sp++ = '\0';
    }
    ret = krb5_string_to_enctype(s, etype);
    if (ret)
        return ret;

    /* Default to normal salt if omitted. */
    *stype = KRB5_KDB_SALTTYPE_NORMAL;
    if (sp == NULL)
        return 0;
    return krb5_string_to_salttype(sp, stype);
}

/*
 * krb5_string_to_keysalts()    - Convert a string representation to a list
 *                                of key/salt tuples.
 */
krb5_error_code
krb5_string_to_keysalts(const char *string, const char *tupleseps,
                        const char *ksaltseps, krb5_boolean dups,
                        krb5_key_salt_tuple **ksaltp, krb5_int32 *nksaltp)
{
    char *p, *ksp;
    char *tlasts = NULL;
    const char *tseps = (tupleseps != NULL) ? tupleseps : default_tupleseps;
    krb5_int32 nksalts = 0;
    krb5_int32 stype;
    krb5_enctype etype;
    krb5_error_code ret = 0;
    krb5_key_salt_tuple *ksalts = NULL, *ksalts_new = NULL;

    *ksaltp = NULL;
    *nksaltp = 0;
    p = strdup(string);
    if (p == NULL)
        return ENOMEM;
    ksp = strtok_r(p, tseps, &tlasts);
    while (ksp != NULL) {
        ret = string_to_keysalt(ksp, ksaltseps, &etype, &stype);
        if (ret)
            goto cleanup;

        /* Ignore duplicate keysalts if caller asks. */
        if (dups || !krb5_keysalt_is_present(ksalts, nksalts, etype, stype)) {
            ksalts_new = realloc(ksalts, (nksalts + 1) * sizeof(*ksalts));
            if (ksalts_new == NULL) {
                ret = ENOMEM;
                goto cleanup;
            }
            ksalts = ksalts_new;
            ksalts[nksalts].ks_enctype = etype;
            ksalts[nksalts].ks_salttype = stype;
            nksalts++;
        }
        ksp = strtok_r(NULL, tseps, &tlasts);
    }
    *ksaltp = ksalts;
    *nksaltp = nksalts;
cleanup:
    if (ret)
        free(ksalts);
    free(p);
    return ret;
}

/*
 * krb5_keysalt_iterate()       - Do something for each unique key/salt
 *                                combination.
 *
 * If ignoresalt set, then salttype is ignored.
 */
krb5_error_code
krb5_keysalt_iterate(ksaltlist, nksalt, ignoresalt, iterator, arg)
    krb5_key_salt_tuple *ksaltlist;
    krb5_int32          nksalt;
    krb5_boolean        ignoresalt;
    krb5_error_code     (*iterator) (krb5_key_salt_tuple *, krb5_pointer);
    krb5_pointer        arg;
{
    int                 i;
    krb5_error_code     kret;
    krb5_key_salt_tuple scratch;

    kret = 0;
    for (i=0; i<nksalt; i++) {
        scratch.ks_enctype = ksaltlist[i].ks_enctype;
        scratch.ks_salttype = (ignoresalt) ? -1 : ksaltlist[i].ks_salttype;
        if (!krb5_keysalt_is_present(ksaltlist,
                                     i,
                                     scratch.ks_enctype,
                                     scratch.ks_salttype)) {
            kret = (*iterator)(&scratch, arg);
            if (kret)
                break;
        }
    }
    return(kret);
}

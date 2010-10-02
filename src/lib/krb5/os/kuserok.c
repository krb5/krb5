/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * lib/krb5/os/kuserok.c
 *
 * Copyright 1990,1993,2007 by the Massachusetts Institute of Technology.
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
 * krb5_kuserok()
 */

#include "k5-int.h"
#if !defined(_WIN32)            /* Not yet for Windows */
#include <stdio.h>
#include <pwd.h>

#if defined(_AIX) && defined(_IBMR2)
#include <sys/access.h>
/* xlc has a bug with "const" */
#define getpwnam(user) getpwnam((char *)user)
#endif

#define MAX_USERNAME 65

#if defined(__APPLE__) && defined(__MACH__)
#include <hfs/hfs_mount.h>      /* XXX */
#define FILE_OWNER_OK(UID)  ((UID) == 0 || (UID) == UNKNOWNUID)
#else
#define FILE_OWNER_OK(UID)  ((UID) == 0)
#endif

enum result { ACCEPT, REJECT, PASS };

/*
 * Find the k5login filename for luser, either in the user's homedir or in a
 * configured directory under the username.
 */
static krb5_error_code
get_k5login_filename(krb5_context context, const char *luser,
                     const char *homedir, char **filename_out)
{
    krb5_error_code ret;
    char *dir, *filename;

    *filename_out = NULL;
    ret = profile_get_string(context->profile, KRB5_CONF_LIBDEFAULTS,
                             KRB5_CONF_K5LOGIN_DIRECTORY, NULL, NULL, &dir);
    if (ret != 0)
        return ret;

    if (dir == NULL) {
        /* Look in the user's homedir. */
        if (asprintf(&filename, "%s/.k5login", homedir) < 0)
            return ENOMEM;
    } else {
        /* Look in the configured directory. */
        if (asprintf(&filename, "%s/%s", dir, luser) < 0)
            ret = ENOMEM;
        profile_release_string(dir);
        if (ret)
            return ret;
    }
    *filename_out = filename;
    return 0;
}

/*
 * Determine whether principal is authorized to log in as luser according to
 * the user's k5login file.  Return ACCEPT if the k5login file authorizes the
 * principal, PASS if the k5login file does not exist, or REJECT if the k5login
 * file exists but does not authorize the principal.  If k5login files are
 * configured to be non-authoritative, pass instead of rejecting.
 */
static enum result
k5login_ok(krb5_context context, krb5_principal principal, const char *luser)
{
    int authoritative = TRUE, gobble;
    enum result result = REJECT;
    char *filename = NULL, *princname = NULL;
    char *newline, linebuf[BUFSIZ], pwbuf[BUFSIZ];
    struct stat sbuf;
    struct passwd pwx, *pwd;
    FILE *fp = NULL;

    if (profile_get_boolean(context->profile, KRB5_CONF_LIBDEFAULTS,
                            KRB5_CONF_K5LOGIN_AUTHORITATIVE, NULL, TRUE,
                            &authoritative) != 0)
        goto cleanup;

    /* Get the local user's homedir and uid. */
    if (k5_getpwnam_r(luser, &pwx, pwbuf, sizeof(pwbuf), &pwd) != 0)
        goto cleanup;

    if (get_k5login_filename(context, luser, pwd->pw_dir, &filename) != 0)
        goto cleanup;

    if (access(filename, F_OK) != 0) {
        result = PASS;
        goto cleanup;
    }

    if (krb5_unparse_name(context, principal, &princname) != 0)
        goto cleanup;

    fp = fopen(filename, "r");
    if (fp == NULL)
        goto cleanup;
    set_cloexec_file(fp);

    /* For security reasons, the .k5login file must be owned either by
     * the user or by root. */
    if (fstat(fileno(fp), &sbuf))
        goto cleanup;
    if (sbuf.st_uid != pwd->pw_uid && !FILE_OWNER_OK(sbuf.st_uid))
        goto cleanup;

    /* Check each line. */
    while (result != ACCEPT && (fgets(linebuf, sizeof(linebuf), fp) != NULL)) {
        newline = strrchr(linebuf, '\n');
        if (newline != NULL)
            *newline = '\0';
        if (strcmp(linebuf, princname) == 0)
            result = ACCEPT;
        /* Clean up the rest of the line if necessary. */
        if (newline == NULL)
            while (((gobble = getc(fp)) != EOF) && gobble != '\n');
    }

cleanup:
    free(princname);
    free(filename);
    if (fp != NULL)
        fclose(fp);
    /* If k5login files are non-authoritative, never reject. */
    return (!authoritative && result == REJECT) ? PASS : result;
}

/*
 * Determine whether principal is authorized to log in as luser according to
 * aname-to-localname translation.  Return ACCEPT if principal translates to
 * luser or PASS if it does not.
 */
static enum result
an2ln_ok(krb5_context context, krb5_principal principal, const char *luser)
{
    krb5_error_code ret;
    char kuser[MAX_USERNAME];

    ret = krb5_aname_to_localname(context, principal, sizeof(kuser), kuser);
    if (ret != 0)
        return PASS;
    return (strcmp(kuser, luser) == 0) ? ACCEPT : PASS;
}

krb5_boolean KRB5_CALLCONV
krb5_kuserok(krb5_context context, krb5_principal principal, const char *luser)
{
    enum result result;

    result = k5login_ok(context, principal, luser);
    if (result == PASS)
        result = an2ln_ok(context, principal, luser);
    return (result == ACCEPT) ? TRUE : FALSE;
}

#else /* _WIN32 */

/*
 * If the given Kerberos name "server" translates to the same name as "luser"
 * (using * krb5_aname_to_lname()), returns TRUE.
 */
krb5_boolean KRB5_CALLCONV
krb5_kuserok(context, principal, luser)
    krb5_context context;
    krb5_principal principal;
    const char *luser;
{
    char kuser[50];

    if (krb5_aname_to_localname(context, principal, sizeof(kuser), kuser))
        return FALSE;

    if (strcmp(kuser, luser) == 0)
        return TRUE;

    return FALSE;
}
#endif /* _WIN32 */

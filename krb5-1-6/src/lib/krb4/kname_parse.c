/*
 * lib/krb4/kname_parse.c
 *
 * Copyright 1987, 1988, 2001 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
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

#include <stdio.h>
#include "krb.h"
#include <string.h>

static int k_isname_unparsed(const char *s);
static int k_isinst_unparsed(const char *s);
static int k_isrealm_unparsed(const char *s);

/*
 * max size of full name
 *
 * XXX This does not account for backslach quoting, and besides we
 * might want to use MAX_K_NAME_SZ.
 */
#define FULL_SZ (ANAME_SZ + INST_SZ + REALM_SZ)

#define NAME    0		/* which field are we in? */
#define INST    1
#define REALM   2

/*
 * This file contains four routines for handling Kerberos names.
 *
 * kname_parse() breaks a Kerberos name into its name, instance,
 * and realm components.
 *
 * k_isname(), k_isinst(), and k_isrealm() check a given string to see if
 * it's a syntactically legitimate respective part of a Kerberos name,
 * returning 1 if it is, 0 if it isn't.
 *
 * Definition of "syntactically legitimate" names is according to
 * the Project Athena Technical Plan Section E.2.1, page 7 "Specifying
 * names", version dated 21 Dec 1987.
 */

/*
 * kname_parse() takes a Kerberos name "fullname" of the form:
 *
 *		username[.instance][@realm]
 *
 * and returns the three components ("name", "instance", and "realm"
 * in the example above) in the given arguments "np", "ip", and "rp".
 *
 * If successful, it returns KSUCCESS.  If there was an error,
 * KNAME_FMT is returned.
 *
 * For proper operation, this routine requires that the ip, np, and rp
 * arguments be initialized, either to null strings, or to default values
 * of name, instance, and realm.  FIXME-gnu:  Does anyone use it this way?
 */

int KRB5_CALLCONV
kname_parse(np, ip, rp, fullname)
    char *np;
    char *ip;
    char *rp;
    char *fullname;
{
    char buf[FULL_SZ];
    char *rnext, *wnext;	/* next char to read, write */
    register char c;
    int backslash;
    int field;

    backslash = 0;
    rnext = buf;
    wnext = np;
    field = NAME;

    if (strlen(fullname) > FULL_SZ)
        return KNAME_FMT;
    (void) strcpy(buf, fullname);

    while ((c = *rnext++)) {
        if (backslash) {
            *wnext++ = c;
            backslash = 0;
            continue;
        }
        switch (c) {
        case '\\':
            backslash++;
            break;
        case '.':
            switch (field) {
            case NAME:
                if (wnext == np)
                    return KNAME_FMT;
                *wnext = '\0';
                field = INST;
                wnext = ip;
                break;
            case INST:		/* We now allow period in instance */
            case REALM:
                *wnext++ = c;
                break;
            default:
                DEB (("unknown field value\n"));
                return KNAME_FMT;
            }
            break;
        case '@':
            switch (field) {
            case NAME:
                if (wnext == np)
                    return KNAME_FMT;
                *ip = '\0';
                /* fall through */
            case INST:
                *wnext = '\0';
                field = REALM;
                wnext = rp;
                break;
            case REALM:
                return KNAME_FMT;
            default:
                DEB (("unknown field value\n"));
                return KNAME_FMT;
            }
            break;
        default:
            *wnext++ = c;
        }
	/*
	 * Paranoia: check length each time through to ensure that we
	 * don't overwrite things.
	 */
	switch (field) {
	case NAME:
	    if (wnext - np >= ANAME_SZ)
		return KNAME_FMT;
	    break;
	case INST:
	    if (wnext - ip >= INST_SZ)
		return KNAME_FMT;
	    break;
	case REALM:
	    if (wnext - rp >= REALM_SZ)
		return KNAME_FMT;
	    break;
	default:
	    DEB (("unknown field value\n"));
	    return KNAME_FMT;
	}
    }
    *wnext = '\0';
    return KSUCCESS;
}

/*
 * k_isname() returns 1 if the given name is a syntactically legitimate
 * Kerberos name; returns 0 if it's not.
 */

int KRB5_CALLCONV
k_isname(s)
    char *s;
{
    register char c;
    int backslash = 0;

    if (!*s)
        return 0;
    if (strlen(s) > ANAME_SZ - 1)
        return 0;
    while((c = *s++)) {
        if (backslash) {
            backslash = 0;
            continue;
        }
        switch(c) {
        case '\\':
            backslash = 1;
            break;
        case '.':
            return 0;
            /* break; */
        case '@':
            return 0;
            /* break; */
        }
    }
    return 1;
}


/*
 * k_isinst() returns 1 if the given name is a syntactically legitimate
 * Kerberos instance; returns 0 if it's not.
 *
 * We now allow periods in instance names -- they are unambiguous.
 */

int KRB5_CALLCONV
k_isinst(s)
    char *s;
{
    register char c;
    int backslash = 0;

    if (strlen(s) > INST_SZ - 1)
        return 0;
    while((c = *s++)) {
        if (backslash) {
            backslash = 0;
            continue;
        }
        switch(c) {
        case '\\':
            backslash = 1;
            break;
        case '@':
            return 0;
            /* break; */
        }
    }
    return 1;
}

/*
 * k_isrealm() returns 1 if the given name is a syntactically legitimate
 * Kerberos realm; returns 0 if it's not.
 */

int KRB5_CALLCONV
k_isrealm(s)
    char *s;
{
    register char c;
    int backslash = 0;

    if (!*s)
        return 0;
    if (strlen(s) > REALM_SZ - 1)
        return 0;
    while((c = *s++)) {
        if (backslash) {
            backslash = 0;
            continue;
        }
        switch(c) {
        case '\\':
            backslash = 1;
            break;
        case '@':
            return 0;
            /* break; */
        }
    }
    return 1;
}

int KRB5_CALLCONV
kname_unparse(
    char	*outFullName,
    const char	*inName,
    const char	*inInstance,
    const char	*inRealm)
{
    const char	*read;
    char	*write = outFullName;

    if (inName == NULL)
	return KFAILURE;

    if (outFullName == NULL)
        return KFAILURE;

    if (!k_isname_unparsed(inName) ||
	((inInstance != NULL) && !k_isinst_unparsed(inInstance)) ||
	((inRealm != NULL) && !k_isrealm_unparsed(inRealm))) {

	return KFAILURE;
    }

    for (read = inName; *read != '\0'; read++, write++) {
	if ((*read == '.') || (*read == '@')) {
	    *write = '\\';
	    write++;
	}
	*write = *read;
    }

    if ((inInstance != NULL) && (inInstance[0] != '\0')) {
	*write = '.';
	write++;
	for (read = inInstance; *read != '\0'; read++, write++) {
	    if (*read == '@') {
		*write = '\\';
		write++;
	    }
	    *write = *read;
	}
    }

    if ((inRealm != NULL) && (inRealm[0] != '\0')) {
	*write = '@';
	write++;
	for (read = inRealm; *read != '\0'; read++, write++) {
	    if (*read == '@') {
		*write = '\\';
		write++;
	    }
	    *write = *read;
	}
    }

    *write = '\0';
    return KSUCCESS;
}

/*
 * k_isname, k_isrealm, k_isinst expect an unparsed realm -- i.e., one where all
 * components have special characters escaped with \. However,
 * for kname_unparse, we need to be able to sanity-check components without \.
 * That's what k_is*_unparsed are for.
 */

static int
k_isname_unparsed(const char *s)
{
    int len = strlen(s);
    const char* c;
    /* Has to be non-empty and has to fit in ANAME_SZ when escaped with \ */

    if (!*s)
        return 0;

    for (c = s; *c != '\0'; c++) {
    	switch (*c) {
	case '.':
	case '@':
	    len++;
	    break;
    	}
    }

    if (len > ANAME_SZ - 1)
        return 0;
    return 1;
}

static int
k_isinst_unparsed(const char *s)
{
    int len = strlen(s);
    const char* c;
    /* Has to fit in INST_SZ when escaped with \ */

    for (c = s; *c != '\0'; c++) {
    	switch (*c) {
	case '.':
	case '@':
	    len++;
	    break;
    	}
    }

    if (len > INST_SZ - 1)
        return 0;
    return 1;
}

static int
k_isrealm_unparsed(const char *s)
{
    int len = strlen(s);
    const char* c;
    /* Has to be non-empty and has to fit in REALM_SZ when escaped with \ */

    if (!*s)
        return 0;

    for (c = s; *c != '\0'; c++) {
    	switch (*c) {
	case '@':
	    len++;
	    break;
    	}
    }

    if (len > REALM_SZ - 1)
        return 0;
    return 1;
}

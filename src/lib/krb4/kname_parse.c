/*
 * kname_parse.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"

#include <stdio.h>
#include "krb.h"
#include <string.h>

/* max size of full name */
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

KRB5_DLLIMP int KRB5_CALLCONV
kname_parse(np, ip, rp, fullname)
    char FAR *np;
    char FAR *ip;
    char FAR *rp;
    char FAR *fullname;
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

    while (c = *rnext++) {
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
    }
    *wnext = '\0';
    if ((strlen(np) > ANAME_SZ - 1) ||
        (strlen(ip) > INST_SZ  - 1) ||
        (strlen(rp) > REALM_SZ - 1))
        return KNAME_FMT;
    return KSUCCESS;
}

/*
 * k_isname() returns 1 if the given name is a syntactically legitimate
 * Kerberos name; returns 0 if it's not.
 */

k_isname(s)
    char *s;
{
    register char c;
    int backslash = 0;

    if (!*s)
        return 0;
    if (strlen(s) > ANAME_SZ - 1)
        return 0;
    while(c = *s++) {
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

k_isinst(s)
    char *s;
{
    register char c;
    int backslash = 0;

    if (strlen(s) > INST_SZ - 1)
        return 0;
    while(c = *s++) {
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

k_isrealm(s)
    char *s;
{
    register char c;
    int backslash = 0;

    if (!*s)
        return 0;
    if (strlen(s) > REALM_SZ - 1)
        return 0;
    while(c = *s++) {
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

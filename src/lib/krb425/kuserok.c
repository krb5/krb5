/*
 * lib/krb425/kuserok.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * kuserok: check if a kerberos principal has
 * access to a local account
 */

#include "krb425.h"

#include <pwd.h>
#include <string.h>
#include <sys/param.h>
#if defined(aix)   /* AIX needs BSD defined to some value for socket.h */
#define _BSD 44
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>

#define OK 0
#ifdef	NOTOK
#undef	NOTOK
#endif
#define NOTOK 1
#define MAX_USERNAME 10

#ifdef unicos61
#ifdef MAXPATHLEN
#undef MAXPATHLEN
#endif
#define MAXPATHLEN PATHSIZE
#endif  /* unicos61 */

#ifndef F_OK
#define F_OK 0
#endif
    
/*
 * Given a Kerberos principal "kdata", and a local username "luser",
 * determine whether user is authorized to login according to the
 * authorization file ("~luser/.klogin" by default).  Returns OK
 * if authorized, NOTOK if not authorized.
 *
 * If there is no account for "luser" on the local machine, returns
 * NOTOK.  If there is no authorization file, and the given Kerberos
 * name "kdata" translates to the same name as "luser" (using
 * krb_kntoln()), returns OK.  Otherwise, if the authorization file
 * can't be accessed, returns NOTOK.  Otherwise, the file is read for
 * a matching principal name, instance, and realm.  If one is found,
 * returns OK, if none is found, returns NOTOK.
 *
 * The file entries are in the format:
 *
 *	name.instance@realm
 *
 * one entry per line.
 *
 * The ATHENA_COMPAT code supports old-style Athena ~luser/.klogin
 * file entries.  See the file "kn_parse.c".
 */


int
kuserok(kdata, luser)
    AUTH_DAT *kdata;
    char   *luser;
{
    struct stat sbuf;
    struct passwd *pwd;
    char pbuf[MAXPATHLEN];
    int isok = NOTOK, rc;
    FILE *fp;
    char kuser[MAX_USERNAME];
    char principal[ANAME_SZ], inst[INST_SZ], realm[REALM_SZ];
    char linebuf[BUFSIZ];
    char *newline;
    int gobble;

    /* no account => no access */
    if ((pwd = (struct passwd *) getpwnam(luser)) == NULL) {
	return(NOTOK);
    }
    (void) strcpy(pbuf, pwd->pw_dir);
    (void) strcat(pbuf, "/.klogin");

    if (access(pbuf, F_OK)) {	 /* not accessible */
	/*
	 * if he's trying to log in as himself, and there is no .klogin file,
	 * let him.  To find out, call
	 * krb_kntoln to convert the triple in kdata to a name which we can
	 * string compare. 
	 */
	if (!krb_kntoln(kdata, kuser) && (strcmp(kuser, luser) == 0)) {
	    return(OK);
	}
    }
    /* open ~/.klogin */
    if ((fp = fopen(pbuf, "r")) == NULL) {
	return(NOTOK);
    }
    /*
     * security:  if the user does not own his own .klogin file,
     * do not grant access
     */
    if (fstat(fileno(fp), &sbuf)) {
	fclose(fp);
	return(NOTOK);
    }
    if (sbuf.st_uid != pwd->pw_uid) {
	fclose(fp);
	return(NOTOK);
    }


    /* check each line */
    while ((isok != OK) && (fgets(linebuf, BUFSIZ, fp) != NULL)) {
	/* null-terminate the input string */
	linebuf[BUFSIZ-1] = '\0';
	newline = NULL;
	/* nuke the newline if it exists */
	if (newline = strchr(linebuf, '\n'))
	    *newline = '\0';
	rc = kname_parse(principal, inst, realm, linebuf);
	if (rc == KSUCCESS) {
	    isok = (strncmp(kdata->pname, principal, ANAME_SZ) ||
		    strncmp(kdata->pinst, inst, INST_SZ) ||
		    strncmp(kdata->prealm, realm, REALM_SZ));
	}
	/* clean up the rest of the line if necessary */
	if (!newline)
	    while (((gobble = getc(fp)) != EOF) && gobble != '\n');
    }
    fclose(fp);
    return(isok);
}

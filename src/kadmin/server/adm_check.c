/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America is assumed
 *   to require a specific license from the United States Government.
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
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 * 
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_adm_check[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <syslog.h>
#include <com_err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#ifndef hpux
#include <arpa/inet.h>
#endif

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/adm_defs.h>
#include <krb5/adm_err.h>
#include "adm_extern.h"

krb5_error_code
adm_check_acl(name_of_client, acl_type)
char *name_of_client;
char *acl_type;
{
    FILE *acl_file;
    char input_string[255];
    char admin_name[255];
#define num_of_privs	5
    char priv[num_of_privs];
    extern char *acl_file_name;
    char *lcl_acl_file;
    int i, j;

    if ((lcl_acl_file = (char *) calloc(1, 80)) == (char *) 0) {
	com_err("adm_check_acl", ENOMEM, "allocating acl file name");
	return(KADM_ENOMEM);		/* No Memory */
    }

    (void) sprintf(lcl_acl_file, "%s", acl_file_name);

    if ((acl_file = fopen(lcl_acl_file, "r")) == NULL) {
	syslog(LOG_ERR, "Cannot open acl file (%s)", acl_file_name);
	free(lcl_acl_file);
	return(KADM_EPERM);
    }

    for ( ;; ) {

	if ((fgets(input_string, sizeof(input_string), acl_file)) == NULL) {
	    syslog(LOG_ERR, "Administrator (%s) not in ACL file (%s)",
		name_of_client, lcl_acl_file);
	    break;		/* Not Found */
	}

	if (input_string[0] == '#') continue;

	i = 0;
	while (!isspace(input_string[i]) && i < strlen(input_string)) {
	    admin_name[i] = input_string[i];
	    i++;
	}

	while (isspace(input_string[i]) && i < strlen(input_string)) {
	    i++;
	}

	priv[0] = priv[1] = priv[2] = priv[3] = priv[4] = '\0';

	j = 0;
	while ((i < strlen(input_string)) && (j < num_of_privs) &&
		(!isspace(input_string[i]))) {
	    priv[j] = input_string[i];
	    i++; j++;
	}

	if (priv[0] == '*') {
	    priv[0] = 'a';		/* Add Priv */
	    priv[1] = 'c';		/* Changepw Priv */
	    priv[2] = 'd';		/* Delete Priv */
	    priv[3] = 'i';		/* Inquire Priv */
	    priv[4] = 'm';		/* Modify Priv */
	}

	if (!strncmp(admin_name, name_of_client, 
		strlen(name_of_client))) {
	    switch(acl_type[0]) {
		case 'a':
		case 'c':
		case 'd':
		case 'i':
		case 'm':
		    for (i = 0; i < num_of_privs; i++) {
			if (priv[i] == acl_type[0]) {
			    fclose(acl_file);
			    free(lcl_acl_file);
			    return(0);          /* Found */			
			}
		    }
		    break;

		default:
		    break;
	    }
	}
    }

    fclose(acl_file);
    free(lcl_acl_file);
    return(KADM_EPERM);
}

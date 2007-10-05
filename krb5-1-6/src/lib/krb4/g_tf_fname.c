/*
 * g_tf_fname.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "krb.h"
#include <string.h>
#include <stdio.h>		/* For EOF */

/*
 * This file contains a routine to extract the fullname of a user
 * from the ticket file.
 */

/*
 * krb_get_tf_fullname() takes four arguments: the name of the 
 * ticket file, and variables for name, instance, and realm to be
 * returned in.  Since the realm of a ticket file is not really fully 
 * supported, the realm used will be that of the the first ticket in 
 * the file as this is the one that was obtained with a password by
 * krb_get_in_tkt().
 */

int KRB5_CALLCONV
krb_get_tf_fullname(ticket_file, name, instance, realm)
  const char *ticket_file;
  char *name;
  char *instance;
  char *realm;
{
    int tf_status;
    CREDENTIALS c;

    /* If ticket cache selector is null, use default cache.  */
    if (ticket_file == 0)
	ticket_file = tkt_string();

    if ((tf_status = tf_init(ticket_file, R_TKT_FIL)) != KSUCCESS)
	return(tf_status);

    if (((tf_status = tf_get_pname(c.pname)) != KSUCCESS) ||
	((tf_status = tf_get_pinst(c.pinst)) != KSUCCESS))
	return (tf_status);
    
    if (name)
	strcpy(name, c.pname);
    if (instance)
	strcpy(instance, c.pinst);
    if ((tf_status = tf_get_cred(&c)) == KSUCCESS) {
	if (realm)
	    strcpy(realm, c.realm);
    }
    else {
	if (tf_status == EOF)
	    return(KFAILURE);
	else
	    return(tf_status);
    }    
    (void) tf_close();
    
    return(tf_status);
}

/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
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
 *
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_kpwd2pwd[] =
"$Id$";
#endif	/* lint || saber */

#include <stdio.h>
#include <krb5/krb5.h>

#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

#ifdef NEVERDEFINE
/*
 *	typedef struct _passwd_phrase_element {
 *	   krb5_data *passwd;
 *	   krb5_data *phrase;
 *	} passwd_phrase_element;
 *
 *	struct type_KRB5_PasswdSequence {
 *	   struct qbuf *passwd;
 *	   struct qbuf *phrase;
 *	};
 *
 *	struct qbuf {
 *	   struct qbuf *qb_forw;	/* doubly-linked list */
 *	   struct qbuf *qb_back;	/*   .. */
 *
 *	   int	    qb_len;		/* length of data */
 *	   char   *qb_data;		/* current pointer into data */
 *	   char    qb_base[1];		/* extensible... */
 *	};
 *
 */
#endif /* NEVERDEFINE */

struct type_KRB5_PasswdSequence *
krb5_pwd_seq2KRB5_PWD__SEQ(val, error)
const register passwd_phrase_element *val;
register int *error;
{
    register struct type_KRB5_PasswdSequence *retval;

    if ((retval = (struct type_KRB5_PasswdSequence *) calloc(1,
		sizeof(struct type_KRB5_PasswdSequence))) == NULL) {
	com_err("kpwd2pwd", 0, "Unable to Allocate PasswdSequence");
	*error = ENOMEM;
	return(0);
    }

    retval->passwd = krb5_data2qbuf(val->passwd);
    if (!retval->passwd) {
	*error = ENOMEM;
	errout:
	   free_KRB5_PasswdSequence(retval);
	   return(0);
    }

    retval->phrase = krb5_data2qbuf(val->phrase);
    if (!retval->phrase) {
	goto errout;
    }

    return(retval);
}

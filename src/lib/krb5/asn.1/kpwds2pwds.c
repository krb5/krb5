/*
 * $Source$
 * $Author$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
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
 * Glue between Kerberos version and ISODE 6.0 version of structures.
 */

#ifdef NEVERDEFINE
/*
 *	encode_generic will return krb_data in the form:
 *		1 Byte (Integer) ==> Password Sequence Count (25)
 *		5 * ADM_MAX_PW_ITERATIONS Sets:
 *			1 Byte (Integer) ==> Length of Passwd (8 - 255)
 *			8 - 255 Bytes (Character) ==> "Password"
 *			1 Byte (Integer) ==> Length of Phrase (8 - 255)
 *			8 - 255 Bytes (Character) ==> "Phrase"
 *
 *	typedef struct _passwd_phrase_element {
 *	   krb5_data passwd;
 *	   krb5_data phrase;
 *	} passwd_phrase_element;
 *
 *	struct type_KRB5_PasswdData {
 *	   integer     passwd__sequence__count;
 *			/* SEQUENCE OF */
 *	   struct element_KRB5_14 {
 *	       struct type_KRB5_PasswdSequence *PasswdSequence;
 *	       struct element_KRB5_14 *next;
 *	   } *passwd__sequence;
 *	};
 *
 *	struct type_KRB5_PasswdSequence {
 *	   struct qbuf *passwd;
 *	   struct qbuf *phrase;
 *	};
 */
#endif /* NEVERDEFINE */

#if !defined(lint) && !defined(SABER)
static char rcsid_kpwds2pwds[] =
"$Id$";
#endif	/* lint || saber */

#include <stdio.h>
#include <krb5/krb5.h>

#include <isode/psap.h>
#include <krb5/asn1.h>
#include "asn1glue.h"

#include <krb5/ext-proto.h>

struct type_KRB5_PasswdData *
krb5_pwd_data2KRB5_PWD__DATA(val, error)
register const krb5_pwd_data *val;
register int *error;
{
    register struct type_KRB5_PasswdData *retval = 0;
    register struct element_KRB5_14 *passwdseq = 0, *rv1 = 0, *rv2;
    passwd_phrase_element **temp;
    register int i;

		/* Allocate PasswdData Structure */
    if ((retval = (struct type_KRB5_PasswdData *) xcalloc(1, 
		sizeof(*retval))) == NULL) {
	*error = ENOMEM;
	return(0);
    }

    retval->passwd__sequence__count = val->sequence_count;
    
    if (val->element) {
	for ( i = 0, temp = (passwd_phrase_element **) val->element; 
		*temp; 
		temp++, i++, rv1 = rv2){
	    if ((rv2 = (struct element_KRB5_14 *) xcalloc(1, 
			sizeof(*rv2))) == NULL) {;
		*error = ENOMEM;
		errout:
		free_KRB5_PasswdData(retval);
		return(0);
	    }

	    if (rv1) rv1->next = rv2;

	    if (!passwdseq) {
		passwdseq = rv2;
	    }

	    rv2->PasswdSequence = 
		krb5_pwd_seq2KRB5_PWD__SEQ(val->element[i],
		error);

	    if (!rv2->PasswdSequence) {
		for (rv1 = passwdseq; rv1; rv1 = rv2) {
		    if (rv1->PasswdSequence) 
			free_KRB5_PasswdSequence(rv1->PasswdSequence);

		    rv2 = rv1->next;
		    xfree(rv1);
		}
	    goto errout;
	    }
	}

        retval->passwd__sequence = passwdseq;
    } else 
	retval->passwd__sequence = 0;

    return(retval);
}

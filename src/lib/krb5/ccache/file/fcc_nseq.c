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
 *
 * This file contains the source code for krb5_fcc_next_cred.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_nseq_c[] =
"$Id$";
#endif /* !lint && !SABER */

#include "fcc.h"

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_fcc_start_seq_get.
 *
 * Modifes:
 * cursor, creds
 * 
 * Effects:
 * Fills in creds with the "next" credentals structure from the cache
 * id.  The actual order the creds are returned in is arbitrary.
 * Space is allocated for the variable length fields in the
 * credentials structure, so the object returned must be passed to
 * krb5_destroy_credential.
 *
 * The cursor is updated for the next call to krb5_fcc_next_cred.
 *
 * Errors:
 * system errors
 */
krb5_error_code
krb5_fcc_next_cred(id, cursor, creds)
   krb5_ccache id;
   krb5_cc_cursor *cursor;
   krb5_creds *creds;
{
#define TCHECK(ret) if (ret != KRB5_OK) goto lose;
     int ret;
     krb5_error_code kret;
     krb5_fcc_cursor *fcursor;

     memset((char *)creds, 0, sizeof(*creds));

     MAYBE_OPEN(id, FCC_OPEN_RDONLY);

     fcursor = (krb5_fcc_cursor *) *cursor;

     ret = lseek(((krb5_fcc_data *) id->data)->fd, fcursor->pos, L_SET);
     if (ret < 0) {
	 ret = krb5_fcc_interpret(errno);
	 MAYBE_CLOSE(id, ret);
	 return ret;
     }

     kret = krb5_fcc_read_principal(id, &creds->client);
     TCHECK(kret);
     kret = krb5_fcc_read_principal(id, &creds->server);
     TCHECK(kret);
     kret = krb5_fcc_read_keyblock(id, &creds->keyblock);
     TCHECK(kret);
     kret = krb5_fcc_read_times(id, &creds->times);
     TCHECK(kret);
     kret = krb5_fcc_read_bool(id, &creds->is_skey);
     TCHECK(kret);
     kret = krb5_fcc_read_flags(id, &creds->ticket_flags);
     TCHECK(kret);
     kret = krb5_fcc_read_addrs(id, &creds->addresses);
     TCHECK(kret);
     kret = krb5_fcc_read_authdata(id, &creds->authdata);
     TCHECK(kret);
     kret = krb5_fcc_read_data(id, &creds->ticket);
     TCHECK(kret);
     kret = krb5_fcc_read_data(id, &creds->second_ticket);
     TCHECK(kret);
     
     fcursor->pos = tell(((krb5_fcc_data *) id->data)->fd);
     cursor = (krb5_cc_cursor *) fcursor;

lose:
     MAYBE_CLOSE(id, kret);		/* won't overwrite kret
					   if already set */
     if (kret != KRB5_OK)
	 krb5_free_cred_contents(creds);
     return kret;
}

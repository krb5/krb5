/*
 * $Source$
 * $Author$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_fcc_next_cred.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_nseq_c[] =
"$Id$";
#endif /* !lint && !SABER */

#include "fcc.h"

/* XXX Deal with kret values */

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

/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_fcc_next_cred.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_nseq_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

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

     bzero((char *)creds, sizeof(*creds));

     if (OPENCLOSE(id)) {
	  ret = open(((krb5_fcc_data *) id->data)->filename, O_RDONLY, 0);
	  if (ret < 0)
	       return krb5_fcc_interpret(errno);
	  ((krb5_fcc_data *) id->data)->fd = ret;
     }

     fcursor = (krb5_fcc_cursor *) *cursor;

     ret = lseek(((krb5_fcc_data *) id->data)->fd, fcursor->pos, L_SET);
     if (ret < 0) {
	 ret = krb5_fcc_interpret(errno);
	 if (OPENCLOSE(id)) {
	     (void) close(((krb5_fcc_data *)id->data)->fd);
	     ((krb5_fcc_data *)id->data)->fd = -1;
	 }
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
     if (OPENCLOSE(id)) {
	  close(((krb5_fcc_data *) id->data)->fd);
	  ((krb5_fcc_data *) id->data)->fd = -1;
     }
     if (kret != KRB5_OK) {
	 if (creds->client)
	     krb5_free_principal(creds->client);
	 if (creds->server)
	     krb5_free_principal(creds->server);
	 if (creds->keyblock.contents)
	     xfree(creds->keyblock.contents);
	 if (creds->ticket.data)
	     xfree(creds->ticket.data);
	 if (creds->second_ticket.data)
	     xfree(creds->second_ticket.data);
	 if (creds->addresses)
	     krb5_free_address(creds->addresses);
	 if (creds->authdata)
	     krb5_free_authdata(creds->authdata);
     }
     return kret;
}

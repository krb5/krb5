/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_next_cred.
 */

#ifndef	lint
static char fcc_nseq_c[] = "$Id$";
#endif	lint

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
 * creds is set to allocated storage which must be freed by the caller
 * via a call to krb5_free_credentials.
 *
 * The cursor is updated for the next call to krb5_fcc_next_cred.
 *
 * Errors:
 * system errors
 */
krb5_error_code
krb5_fcc_next_cred(id, creds, cursor)
   krb5_ccache id;
   krb5_creds *creds;
   krb5_cc_cursor *cursor;
{
     int ret;
     krb5_error_code kret;
     krb5_fcc_cursor *fcursor;

#ifdef OPENCLOSE
     ret = open(((krb5_fcc_data *) id->data)->filename, O_RDONLY, 0);
     if (ret < 0)
	  return errno;
     ((krb5_fcc_data *) id->data)->fd = ret;
#endif

     fcursor = (krb5_fcc_cursor *) cursor;

     ret = lseek(((krb5_fcc_data *) id->data)->fd, fcursor->pos, L_SET);
     if (ret < 0)
	  return errno;

     creds = (krb5_creds *) malloc(sizeof(krb5_creds));
     if (creds == NULL)
	  return KRB5_NOMEM;

     kret = krb5_fcc_read_principal(&creds->client);
     kret = krb5_fcc_read_principal(&creds->server);
     kret = krb5_fcc_read_keyblock(&creds->keyblock);
     kret = krb5_fcc_read_times(&creds->times);
     kret = krb5_fcc_read_bool(&creds->is_skey);
     kret = krb5_fcc_read_flags(&creds->ticket_flags);
     kret = krb5_fcc_read_data(&creds->ticket);
     kret = krb5_fcc_read_data(&creds->second_ticket);

     fcursor->pos = tell(((krb5_fcc_data *) id->data)->fd);
     cursor = (krb5_cc_cursor *) fcursor;

#ifdef OPENCLOSE
     close(((krb5_fcc_data *) id->data)->fd);
#endif

     return KRB5_OK;
}

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
 * This file contains the source code for krb5_fcc_start_seq_get.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_sseq_c[] = "$Id$";
#endif /* !lint && !SABER */

#include "fcc.h"

/*
 * Effects:
 * Prepares for a sequential search of the credentials cache.
 * Returns and krb5_cc_cursor to be used with krb5_fcc_next_cred and
 * krb5_fcc_end_seq_get.
 *
 * If the cache is modified between the time of this call and the time
 * of the final krb5_fcc_end_seq_get, the results are undefined.
 *
 * Errors:
 * KRB5_CC_NOMEM
 * system errors
 */
krb5_error_code
krb5_fcc_start_seq_get(id, cursor)
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     krb5_fcc_cursor *fcursor;
     int ret = KRB5_OK;
     
     fcursor = (krb5_fcc_cursor *) malloc(sizeof(krb5_fcc_cursor));
     if (fcursor == NULL)
	  return KRB5_CC_NOMEM;
     if (OPENCLOSE(id)) {
	  ret = krb5_fcc_open_file(id, FCC_OPEN_RDONLY);
	  if (ret) {
	      xfree(fcursor);
	      return ret;
	  }
     }
     else
	  /* seek after the version number */
	  lseek(((krb5_fcc_data *) id->data)->fd, sizeof(krb5_int16), L_SET);

     /* Make sure we start reading right after the primary principal */

     krb5_fcc_skip_principal(id);
     fcursor->pos = tell(((krb5_fcc_data *) id->data)->fd);
     *cursor = (krb5_cc_cursor) fcursor;

     MAYBE_CLOSE(id, ret);
     return ret;
}

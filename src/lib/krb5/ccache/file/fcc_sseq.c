/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This file contains the source code for krb5_fcc_start_seq_get.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_sseq_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

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
 * KRB5_NOMEM
 * system errors
 */
krb5_error_code
krb5_fcc_start_seq_get(id, cursor)
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     krb5_fcc_cursor *fcursor;
     int ret;
     
     fcursor = (krb5_fcc_cursor *) malloc(sizeof(krb5_fcc_cursor));
     if (fcursor == NULL)
	  return KRB5_NOMEM;

     /* Make sure we start reading right after the primary principal */
#ifdef OPENCLOSE
     ret = open(((krb5_fcc_data *) id->data)->filename, O_RDONLY, 0);
     if (ret < 0)
	  return errno;
     ((krb5_fcc_data *) id->data)->fd = ret;
#else
     lseek(((krb5_fcc_data *) id->data)->fd, 0, L_SET);
#endif

     krb5_fcc_skip_principal(id);
     fcursor->pos = tell(((krb5_fcc_data *) id->data)->fd);
     *cursor = (krb5_cc_cursor *) fcursor;

#ifdef OPENCLOSE
     close(((krb5_fcc_data *) id->data)->fd);
#endif

     return KRB5_OK;
}

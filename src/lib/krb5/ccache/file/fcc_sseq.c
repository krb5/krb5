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

#ifndef	lint
static char fcc_sseq_c[] = "$Id$";
#endif	lint

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
krb5_error
krb5_fcc_start_seq_get(krb5_ccache id, krb5_cc_cursor *cursor)
{
     krb5_fcc_cursor *fcursor;
     
     fcursor = (krb5_cc_cursor) malloc(sizeof(krb5_fcc_cursor));
     if (fcursor == NULL)
	  return KRB5_NOMEM;

     /* Make sure we start reading right after the primary principal */
#ifdef OPENCLOSE
     ret = open(id->data->filename, O_RDONLY, 0);
     if (ret < 0)
	  return errno;
     id->data->fd = ret;
#else
     lseek(id->data->fd, 0, L_SET);
#endif

     krb5_fcc_skip_pprincipal(id);
     fcursor->pos = tell(id->data->fd);
     cursor = (krb5_cc_cursor) fcursor;

#ifdef OPENCLOSE
     close(id->data->fd);
#endif
}

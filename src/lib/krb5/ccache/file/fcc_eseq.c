/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_fcc_end_seq_get.
 */

#if !defined(lint) && !defined(SABER)
static char fcc_eseq_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>
#include "fcc.h"

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_fcc_start_seq_get.
 *
 * Modifies:
 * id, cursor
 *
 * Effects:
 * Finishes sequential processing of the file credentials ccache id,
 * and invalidates the cursor (it must never be used after this call).
 */
/* ARGSUSED */
krb5_error_code
krb5_fcc_end_seq_get(id, cursor)
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
     if (OPENCLOSE(id)) {
	  close(((krb5_fcc_data *) id->data)->fd);
	  ((krb5_fcc_data *) id->data)->fd = -1;
     }

     xfree((krb5_fcc_cursor *) *cursor);

     return KRB5_OK;
}



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
 * This file contains the source code for krb5_fcc_end_seq_get.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_fcc_eseq_c[] =
"$Id$";
#endif /* !lint && !SABER */

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
     int kret = KRB5_OK;
     
     /* don't close; it may be left open by the caller,
	and if not, fcc_start_seq_get and/or fcc_next_cred will do the
	MAYBE_CLOSE.
     MAYBE_CLOSE(id, kret); */
     xfree((krb5_fcc_cursor *) *cursor);

     return kret;
}



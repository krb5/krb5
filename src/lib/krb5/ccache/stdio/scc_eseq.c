/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the source code for krb5_scc_end_seq_get.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_eseq_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>
#include "scc.h"

/*
 * Requires:
 * cursor is a krb5_cc_cursor originally obtained from
 * krb5_scc_start_seq_get.
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
krb5_scc_end_seq_get(id, cursor)
   krb5_ccache id;
   krb5_cc_cursor *cursor;
{
    int ret = KRB5_OK;
/*    MAYBE_CLOSE (id, ret);*/

    xfree((krb5_scc_cursor *) *cursor);

    return ret;
}



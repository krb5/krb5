/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * This file contains the structure krb5_cc_dfl_ops.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_scc_defops_c[] = "$Id$";
#endif /* !lint && !SABER */

#include <krb5/copyright.h>

#include "scc.h"

krb5_cc_ops krb5_cc_stdio_ops = {
     "STDIO",
     krb5_scc_get_name,
     krb5_scc_resolve,
     krb5_scc_generate_new,
     krb5_scc_initialize,
     krb5_scc_destroy,
     krb5_scc_close,
     krb5_scc_store,
     krb5_scc_retrieve,
     krb5_scc_get_principal,
     krb5_scc_start_seq_get,
     krb5_scc_next_cred,
     krb5_scc_end_seq_get,
     NULL, /* XXX krb5_scc_remove, */
     krb5_scc_set_flags,
};

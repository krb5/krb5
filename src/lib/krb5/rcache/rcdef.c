/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * replay cache default operations vector.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_rcdef_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include "rc_dfl.h"

krb5_rc_ops krb5_rc_dfl_ops =
 {
  "dfl",
  krb5_rc_dfl_init,
  krb5_rc_dfl_recover,
  krb5_rc_dfl_destroy,
  krb5_rc_dfl_close,
  krb5_rc_dfl_store,
  krb5_rc_dfl_expunge,
  krb5_rc_dfl_get_span,
  krb5_rc_dfl_get_name,
  krb5_rc_dfl_resolve
 }
;

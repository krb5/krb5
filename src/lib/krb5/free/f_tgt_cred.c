/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * krb5_free_tgt_creds()
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_f_tgt_cred_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>

void
krb5_free_tgt_creds(tgts)
krb5_creds **tgts;
{
    register krb5_creds **tgtpp;
    for (tgtpp = tgts; *tgtpp; tgtpp++)
	krb5_free_creds(*tgtpp);
    xfree(tgts);
}

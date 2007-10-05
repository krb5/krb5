/*
 * lib/krb4/rd_err.c
 *
 * Copyright 1986, 1987, 1988, 2000 by the Massachusetts Institute of
 * Technology.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * Steve Miller    Project Athena  MIT/DEC
 */

#include <string.h>

#include "krb.h"
#include "prot.h"

/*
 * Given an AUTH_MSG_APPL_ERR message, "in" and its length "in_length",
 * return the error code from the message in "code" and the text in
 * "m_data" as follows:
 *
 *	m_data->app_data	points to the error text
 *	m_data->app_length	points to the length of the error text
 *
 * If all goes well, return RD_AP_OK.  If the version number
 * is wrong, return RD_AP_VERSION, and if it's not an AUTH_MSG_APPL_ERR
 * type message, return RD_AP_MSG_TYPE.
 *
 * The AUTH_MSG_APPL_ERR message format can be found in mk_err.c
 */

int KRB5_CALLCONV
krb_rd_err(in, in_length, code, m_data)
    u_char *in;                 /* pointer to the msg received */
    u_long in_length;           /* of in msg */
    long *code;                 /* received error code */
    MSG_DAT *m_data;
{
    register u_char *p;
    int le;
    unsigned KRB4_32 raw_code;

    p = in;                     /* beginning of message */

    if (in_length < 1 + 1 + 4)
	return RD_AP_MODIFIED;	/* XXX should have better error code */
    if (*p++ != KRB_PROT_VERSION)
        return RD_AP_VERSION;
    if (((*p) & ~1) != AUTH_MSG_APPL_ERR)
        return RD_AP_MSG_TYPE;
    le = *p++ & 1;

    KRB4_GET32(raw_code, p, le);
    *code = raw_code;		/* XXX unsigned->signed conversion! */

    m_data->app_data = p;       /* we're now at the error text
                                 * message */
    m_data->app_length = p - in;

    return RD_AP_OK;           /* OK == 0 */
}

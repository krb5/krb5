/*
 * kdc/kdc_preauth.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * Preauthentication routines for the KDC.
 */

#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"
#include <stdio.h>

typedef krb5_error_code (verify_proc)
    KRB5_PROTOTYPE((krb5_context, krb5_principal client,
		    krb5_address **src_addr,
		    krb5_data *data));

typedef krb5_error_code (edata_proc)
    KRB5_PROTOTYPE((krb5_context, krb5_db_entry *client,
		    krb5_pa_data *data));

typedef struct _krb5_preauth_systems {
    int		type;
    int		flags;
    edata_proc	*get_edata;
    verify_proc	*verify;
} krb5_preauth_systems;

/*
 * Preauth property flags
 */
#define PA_ENCRYPT	0x00000001
#define PA_HARDWARE	0x00000002

static krb5_preauth_systems preauth_systems[] = {
    {
        KRB5_PADATA_ENC_UNIX_TIME,
        PA_ENCRYPT,
        0,
	0,
    },
    {
	KRB5_PADATA_ENC_SANDIA_SECURID,
	PA_ENCRYPT | PA_HARDWARE,
	0,
	0,
    },
    { -1,}
};

#define MAX_PREAUTH_SYSTEMS (sizeof(preauth_systems)/sizeof(preauth_systems[0]))

const char *missing_required_preauth(client, server, enc_tkt_reply)
    krb5_db_entry *client, *server;
    krb5_enc_tkt_part *enc_tkt_reply;
{
#if 0
    /*
     * If this is the pwchange service, and the pre-auth bit is set,
     * allow it even if the HW preauth would normally be required.
     * 
     * Sandia national labs wanted this for some strange reason... we
     * leave it disabled normally.
     */
    if (isflagset(server->attributes, KRB5_KDB_PWCHANGE_SERVICE) &&
	isflagset(enc_tkt_reply->flags, TKT_FLG_PRE_AUTH))
	return 0;
#endif
    
    if (isflagset(client->attributes, KRB5_KDB_REQUIRES_PRE_AUTH) &&
	 !isflagset(enc_tkt_reply->flags, TKT_FLG_PRE_AUTH))
	return "NEEDED_PREAUTH";
    
    if (isflagset(client->attributes, KRB5_KDB_REQUIRES_HW_AUTH) &&
	!isflagset(enc_tkt_reply->flags, TKT_FLG_HW_AUTH))
	return "NEEDED_HW_PREAUTH";

    return 0;
}

void get_preauth_hint_list(client, server, e_data)
    krb5_db_entry *client, *server;
    krb5_data *e_data;
{
    int hw_only;
    krb5_preauth_systems *ap;
    krb5_pa_data **pa_data, **pa;
    krb5_data *edat;
    krb5_error_code retval;
    
    /* Zero these out in case we need to abort */
    e_data->length = 0;
    e_data->data = 0;
    
    hw_only = isflagset(client->attributes, KRB5_KDB_REQUIRES_HW_AUTH);
    pa_data = malloc(sizeof(krb5_pa_data *) * (MAX_PREAUTH_SYSTEMS+1));
    if (pa_data == 0)
	return;
    memset(pa_data, 0, sizeof(krb5_pa_data *) * (MAX_PREAUTH_SYSTEMS+1));
    pa = pa_data;

    for (ap = preauth_systems; ap->type != -1; ap++) {
	if (hw_only && !(ap->flags & PA_HARDWARE))
	    continue;
	*pa = malloc(sizeof(krb5_pa_data));
	if (*pa == 0)
	    goto errout;
	memset(pa, 0, sizeof(krb5_pa_data));
	(*pa)->magic = KV5M_PA_DATA;
	(*pa)->pa_type = ap->type;
	if (ap->get_edata)
	    (ap->get_edata)(kdc_context, client, *pa);
	pa++;
    }
    retval = encode_krb5_padata_sequence((const krb5_pa_data **) pa_data,
					 &edat);
    if (retval)
	goto errout;
    *e_data = *edat;
    free(edat);

errout:
    krb5_free_pa_data(kdc_context, pa_data);
    return;
}


			

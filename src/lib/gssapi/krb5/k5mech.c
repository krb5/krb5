/*
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */
 
/* XXX: I know where to find this header, but it really is using a
 * private interface.  I dont want to export the gss_mechanism
 * structure, so I hide it in a non-published header.  Thats ok,
 * we know where to find it.
 */
#if defined(__MWERKS__) || defined(applec) || defined(THINK_C)
#include "mglueP.h"
#else
#include "../mechglue/mglueP.h"
#endif

#include "gssapiP_krb5.h"
/*
 * These are the extern declarations, one group per mechanism. They are
 * contained in the files named <mech>_gssd_extern_srvr.conf.
 */

/* ident  "@(#)krb5_gssd_extern_srvr.conf 1.10     95/08/01 SMI" */

OM_uint32 krb5_gss_internal_release_oid
      PROTOTYPE((void *,                /* context */
       OM_uint32 *,           /* minor_status */
       gss_OID *              /* OID */
      ));

extern OM_uint32 krb5_gss_get_context
	   PROTOTYPE((void**
	   ));

extern int krb5_pname_to_uid
             PROTOTYPE((void *,           /* context */
              char *,		/* principal name */
              gss_OID,		/* name_type */
	      gss_OID,		/* mech_type */
              uid_t *		/* uid (OUT) */
             ));

/*
 * This is the declaration of the mechs_array table for Kerberos V5.
 * If the gss_mechanism structure changes, so should this array!  I
 * told you it was a private interface!
 */

/* ident  "@(#)krb5_gssd_init_srvr.conf 1.16     95/08/07 SMI" */

static struct gss_config krb5_mechanism =
	{{5,"\053\005\001\005\002"},
	0,				/* context, to be filled */
	krb5_gss_acquire_cred,
	krb5_gss_release_cred,
	krb5_gss_init_sec_context,
	krb5_gss_accept_sec_context,
	krb5_gss_process_context_token,
	krb5_gss_delete_sec_context,
	krb5_gss_context_time,
	krb5_gss_sign,
	krb5_gss_verify,
	krb5_gss_seal,
	krb5_gss_unseal,
	krb5_gss_display_status,
	krb5_gss_indicate_mechs,
	krb5_gss_compare_name,
	krb5_gss_display_name,
	krb5_gss_import_name,
	krb5_gss_release_name,
	krb5_gss_inquire_cred,
	krb5_gss_add_cred,
	krb5_gss_export_sec_context,
	krb5_gss_import_sec_context,
	krb5_gss_inquire_cred_by_mech,
	krb5_gss_inquire_names_for_mech,
	krb5_gss_inquire_context,
	krb5_gss_internal_release_oid,
	krb5_gss_wrap_size_limit,     
	krb5_pname_to_uid,
	};

#include "k5-int.h"


OM_uint32
krb5_gss_get_context(context)
void **	context;
{
    if (context == NULL)
	return GSS_S_FAILURE;
    if (kg_context) {
	*context = kg_context;
	return (GSS_S_COMPLETE);
    }
    if (krb5_init_context(&kg_context))
	return GSS_S_FAILURE;
    if (krb5_ser_context_init(kg_context) ||
	krb5_ser_auth_context_init(kg_context) ||
	krb5_ser_ccache_init(kg_context) ||
	krb5_ser_rcache_init(kg_context) ||
	krb5_ser_keytab_init(kg_context) ||
	kg_ser_context_init(kg_context)) {
	krb5_free_context(kg_context);
	kg_context = 0;
	return (GSS_S_FAILURE);
    }
    *context = kg_context;
    return GSS_S_COMPLETE;
}

gss_mechanism
krb5_gss_initialize()
{
    krb5_gss_get_context(&(krb5_mechanism.context));
    return (&krb5_mechanism);
}

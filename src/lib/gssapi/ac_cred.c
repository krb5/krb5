/*
 * ac_cred.c --- gss_acquire_cred
 * 
 * $Source$
 * $Author$
 * $Header$
 * 
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

/*
 * Note: There are really two kinds of credentials in Kerberos V5...
 * the first kind is for users, and we use a krb5_ccache to get at
 * that.  The second kind is for servers, and we use a krb5_keytab to
 * point at that.
 *
 * It is possible to convert from one to another, but we don't address
 * that right now.
 *
 * XXX We need to do something with time_rec.
 */

#include <gssapi.h>

char *gss_krb5_fetchfrom = NULL;

OM_uint32 gss_acquire_cred(minor_status, desired_name, time_req,
			   desired_mechs, cred_usage, output_cred_handle,
			   actual_mechs, time_rec)
	OM_uint32	*minor_status;
	gss_name_t	desired_name;
	OM_uint32	time_req;
	gss_OID_set	desired_mechs;
	int		cred_usage;
	gss_cred_id_t	*output_cred_handle;
	gss_OID_set	*actual_mechs;
	OM_uint32	*time_rec;
{
	krb5_keytab_entry	entry;
	krb5_keytab	keytabid;
	int		do_kerberos = 0;
	int		i;
	krb5_error_code	retval;
	
	*minor_status = 0;

	/*
	 * Figure out which mechanism we should be using.
	 */
	if (desired_mechs == GSS_C_NULL_OID_SET)
		do_kerberos++;
	else {
		for (i = 0; i <= desired_mechs->count; i++) {
			if (gss_compare_OID(&desired_mechs->elements[i],
					   &gss_OID_krb5))
				do_kerberos++;
		}
	}

	/*
	 * Should we return failure here?
	 */
	if (!do_kerberos)
		return(gss_make_re(GSS_RE_FAILURE));
	output_cred_handle->cred_flags = 0;

	/*
	 * This is Kerberos V5 specific stuff starting here.
	 * First, let's try to search the keytab file.
	 * Applications that know what they are doing can mess with
	 * the variable gss_krb_fetchfrom.  Otherwise, we use the
	 * system default keytab file.
	 */
	if (*minor_status = krb5_copy_principal(desired_name,
						&output_cred_handle->principal)) {
		return(gss_make_re(GSS_RE_FAILURE));
	}
	if (gss_krb5_fetchfrom) {
		/* use the named keytab */
		retval = krb5_kt_resolve(gss_krb5_fetchfrom, &keytabid);
	} else {
		/* use default keytab */
		retval = krb5_kt_default(&keytabid);
	}
	if (!retval) {
		retval = krb5_kt_get_entry(keytabid, desired_name, 0, 
						  &entry);
		(void) krb5_kt_close(keytabid);
		if (!retval) {
			output_cred_handle->cred_flags |= GSS_KRB_HAS_SRVTAB;
			output_cred_handle->kvno = entry.vno;
			output_cred_handle->srvtab = entry.key;
			krb5_free_principal(entry.principal);
		}
	}
	/*
	 * Now let's try opening the default credentials file and see
	 * if it contains the desired name.  We could try searching
	 * some directory (like /tmp) if we really cared, but not for
	 * now.
	 *
	 * We're not even looking in the default credentials file
	 * right now.  XXX
	 */

	/*
	 * We're done, clean up and get out.
	 */
	if (actual_mechs) {
		gss_OID_set	set;

		if (!(set = (gss_OID_set)
		      malloc (sizeof(struct gss_OID_set_desc)))) {
			*minor_status = ENOMEM;
			return(gss_make_re(GSS_RE_FAILURE));
		}
		set->count = 1;
		set->elements = &gss_OID_krb5;
		*actual_mechs = set;
	}
	return(GSS_S_COMPLETE);

}


/*
 * lib/kadm/adm_kw_enc.c
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
 */

/*
 * adm_kw_enc.c	- routines to encode principal attributes in keyword-value
 *		  pairs.
 */
#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"


/*
 * format_kw_string()	- Format a keyword=<string> pair.
 * 
 * Work routine for other string-based formatters also.
 */
static krb5_error_code
format_kw_string(datap, kwordp, valp)
    krb5_data	*datap;
    char	*kwordp;
    char	*valp;
{
    krb5_error_code	retval;
    char		fbuffer[BUFSIZ];

    retval = ENOMEM;
    sprintf(fbuffer,"%s=%s", kwordp, valp);
    datap->data = (char *) malloc(strlen(fbuffer)+1);
    if (datap->data) {
	datap->length = strlen(fbuffer);
	strcpy(datap->data, fbuffer);
	retval = 0;
    }
    return(retval);
}

/*
 * format_kw_integer()	- Format a keyword=<integer> pair.
 */
static krb5_error_code
format_kw_integer(datap, kwordp, val)
    krb5_data	*datap;
    char	*kwordp;
    krb5_ui_4	val;
{
    krb5_error_code	retval;
    char		fbuffer[BUFSIZ];

    retval = ENOMEM;
    sprintf(fbuffer,"%s=", kwordp);
    datap->data = (char *) malloc(strlen(fbuffer)+sizeof(krb5_ui_4));
    if (datap->data) {
	datap->length = strlen(fbuffer);
	strcpy(datap->data, fbuffer);
	datap->data[datap->length]   = (unsigned char) ((val >> 24) & 0xff);
	datap->data[datap->length+1] = (unsigned char) ((val >> 16) & 0xff);
	datap->data[datap->length+2] = (unsigned char) ((val >> 8) & 0xff);
	datap->data[datap->length+3] = (unsigned char) (val & 0xff);
	datap->length += sizeof(krb5_ui_4);
	retval = 0;
    }
    return(retval);
}

/*
 * format_kw_gentime()	- Format a keyword=<general-time> pair.
 *
 * XXX - should this routine know so much about how generaltime is encoded?
 */
static krb5_error_code
format_kw_gentime(datap, kwordp, timep)
    krb5_data		*datap;
    char		*kwordp;
    krb5_timestamp	*timep;
{
    krb5_error_code	retval;
    char		fbuffer[BUFSIZ];
    time_t		tval;
    struct tm		*time_gmt;

    retval = EINVAL;
    tval = (time_t) *timep;
    time_gmt = gmtime(&tval);
    if (time_gmt) {
	sprintf(fbuffer,"%04d%02d%02d%02d%02d%02dZ",
		time_gmt->tm_year+1900,
		time_gmt->tm_mon+1,
		time_gmt->tm_mday,
		time_gmt->tm_hour,
		time_gmt->tm_min,
		time_gmt->tm_sec);
	retval = format_kw_string(datap, kwordp, fbuffer);
    }
    return(retval);
}

/*
 * format_kw_tagged()	- Format a <tagged>=<taglist>...<value> list.
 */
static krb5_error_code
format_kw_tagged(datap, kwordp, ntags, taglist, vallen, val)
    krb5_data	*datap;
    char	*kwordp;
    const int	ntags;
    krb5_int32	*taglist;
    krb5_int32	vallen;
    krb5_octet	*val;
{
    krb5_error_code	retval;
    unsigned char	*cp;
    int			i;

    /* Calculate the size required:
     *	strlen(kwordp) + 1 for "kword"=
     *	4 * ntags for tags
     *	vallen for value;
     */
    datap->data = (char *) malloc(strlen(kwordp)+
				  1+
				  (ntags*sizeof(krb5_int32))+
				  vallen+1);
    if (datap->data) {
	datap->length = strlen(kwordp)+1+(ntags*sizeof(krb5_int32))+vallen;
	cp = (unsigned char *) datap->data;
	cp[datap->length] = '\0';
	sprintf((char *) cp, "%s=", kwordp);
	cp += strlen((char *) cp);
	for (i=0; i<ntags; i++) {
	    cp[0] = (unsigned char) ((taglist[i] >> 24) & 0xff);
	    cp[1] = (unsigned char) ((taglist[i] >> 16) & 0xff);
	    cp[2] = (unsigned char) ((taglist[i] >> 8) & 0xff);
	    cp[3] = (unsigned char) (taglist[i] & 0xff);
	    cp += sizeof(krb5_int32);
	}
	if (val && vallen)
	    memcpy(cp, val, vallen);
	retval = 0;
    }
    return(retval);
}

#if ! defined(_WINDOWS) && ! defined(_MACINTOSH)
/*
 * krb5_adm_dbent_to_proto()	- Convert database a database entry into
 *				  an external attribute list.
 *
 * "valid" controls the generation of "datap" and "nentp".  For each
 * corresponding bit in "valid" a keyword-value pair is generated from
 * values in "dbentp" or "password" and put into "datap".  The number of
 * generated pairs is returned in "nentp".  Additionally, the KRB5_ADM_M_SET
 * and KRB5_ADM_M_GET bits control whether we are generating attribute lists
 * for a "set" operation or a "get" operation.  One of these bits must be
 * specified.
 *
 * Successful callers must free the storage for datap and datap->data
 * either manually or using krb5_free_adm_data().
 */
krb5_error_code
krb5_adm_dbent_to_proto(kcontext, valid, dbentp, password, nentp, datap)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    krb5_ui_4		valid;		/* Valid bitmask	*/ /* In */
    krb5_db_entry	*dbentp;	/* Database entry	*/ /* In */
    char		*password;	/* New password for set	*/ /* In */
    krb5_int32		*nentp;		/* Number of components	*/ /* Out */
    krb5_data		**datap;	/* Output list		*/ /* Out */
{
    krb5_error_code	kret;
    krb5_data		*outlist;
    size_t		n2alloc;
    int			outindex;
    krb5_boolean	is_set;
    krb5_ui_4		tmp;
    krb5_int32		taglist[4];
    krb5_tl_data	*tl_data;
    int			keyind, attrind;

    kret = 0;
    /* First check out whether this is a set or get and the mask */
    is_set = ((valid & KRB5_ADM_M_SET) == KRB5_ADM_M_SET);
    if ((is_set && ((valid & ~KRB5_ADM_M_SET_VALID) != 0)) ||
	(!is_set && ((valid & ~KRB5_ADM_M_GET_VALID) != 0)) ||
	(!is_set && ((valid & KRB5_ADM_M_GET) == 0)))
	return(EINVAL);

    /*
     * Compute the number of elements to allocate.  First count set bits.
     */
    n2alloc = 0;
    for (tmp = valid & ~(KRB5_ADM_M_SET|KRB5_ADM_M_GET);
	 tmp;
	 tmp >>= 1) {
	if (tmp & 1)
	    n2alloc++;
    }
    if (valid & KRB5_ADM_M_AUXDATA)
	n2alloc += (dbentp->n_tl_data - 1);
    /*
     * NOTE: If the number of per-key attributes increases, you must increase
     * the 3 below.  The 3 represents 1 for key version, 1 for key type and
     * one for salt type.
     */
    if (valid & KRB5_ADM_M_KEYDATA)
	n2alloc += ((dbentp->n_key_data*3)-1);

    n2alloc *= sizeof(krb5_data);
    outindex = 0;
    outlist = (krb5_data *) malloc(n2alloc);
    if (outlist) {
	/* Clear out the output data list */
	memset((char *) outlist, 0, n2alloc);

	/* Handle password only for set request */
	if (is_set &&
	    ((valid & KRB5_ADM_M_PASSWORD) != 0) &&
	    password) {
	    if (kret = format_kw_string(&outlist[outindex],
					KRB5_ADM_KW_PASSWORD,
					password))
		goto choke;
	    else
		outindex++;
	}
	/* Handle maximum ticket lifetime */
	if ((valid & KRB5_ADM_M_MAXLIFE) != 0) {
	    if (kret = format_kw_integer(&outlist[outindex],
					 KRB5_ADM_KW_MAXLIFE,
					 (krb5_ui_4) dbentp->max_life))
		goto choke;
	    else
		outindex++;
	}
	/* Handle maximum renewable ticket lifetime */
	if ((valid & KRB5_ADM_M_MAXRENEWLIFE) != 0) {
	    if (kret =
		format_kw_integer(&outlist[outindex],
				  KRB5_ADM_KW_MAXRENEWLIFE,
				  (krb5_ui_4) dbentp->max_renewable_life))
		goto choke;
	    else
		outindex++;
	}
	/* Handle principal expiration */
	if ((valid & KRB5_ADM_M_EXPIRATION) != 0) {
	    if (kret = format_kw_gentime(&outlist[outindex],
					 KRB5_ADM_KW_EXPIRATION,
					 &dbentp->expiration))
		goto choke;
	    else
		outindex++;
	}
	/* Handle password expiration */
	if ((valid & KRB5_ADM_M_PWEXPIRATION) != 0) {
	    if (kret = format_kw_gentime(&outlist[outindex],
					 KRB5_ADM_KW_PWEXPIRATION,
					 &dbentp->pw_expiration))
		goto choke;
	    else
		outindex++;
	}
	/* Random key */
	if ((valid & KRB5_ADM_M_RANDOMKEY) != 0) {
	    if (kret = format_kw_integer(&outlist[outindex],
					 KRB5_ADM_KW_RANDOMKEY,
					 1))
		goto choke;
	    else
		outindex++;
	}
	/* Handle flags */
	if ((valid & KRB5_ADM_M_FLAGS) != 0) {
	    if (kret = format_kw_integer(&outlist[outindex],
					 KRB5_ADM_KW_FLAGS,
					 (krb5_ui_4) dbentp->attributes))
		goto choke;
	    else
		outindex++;
	}
	/* Handle last successful password entry */
	if (!is_set &&
	    ((valid & KRB5_ADM_M_LASTSUCCESS) != 0)) {
	    if (kret = format_kw_gentime(&outlist[outindex],
					 KRB5_ADM_KW_LASTSUCCESS,
					 &dbentp->last_success))
		goto choke;
	    else
		outindex++;
	}
	/* Handle last failed password attempt */
	if (!is_set &&
	    ((valid & KRB5_ADM_M_LASTFAILED) != 0)) {
	    if (kret = format_kw_gentime(&outlist[outindex],
					 KRB5_ADM_KW_LASTFAILED,
					 &dbentp->last_failed))
		goto choke;
	    else
		outindex++;
	}
	/* Handle number of failed password attempts */
	if (!is_set &&
	    ((valid & KRB5_ADM_M_FAILCOUNT) != 0)) {
	    if (kret = format_kw_integer(&outlist[outindex],
					 KRB5_ADM_KW_FAILCOUNT,
					 (krb5_ui_4) dbentp->fail_auth_count))
		goto choke;
	    else
		outindex++;
	}

	/* Handle the auxiliary data */
	if ((valid & KRB5_ADM_M_AUXDATA) != 0) {
	    for (tl_data = dbentp->tl_data; tl_data; tl_data =
		 tl_data->tl_data_next) {
		taglist[0] = (krb5_int32) tl_data->tl_data_type;
		if (kret = format_kw_tagged(&outlist[outindex],
					    KRB5_ADM_KW_AUXDATA,
					    1,
					    taglist,
					    (krb5_int32) tl_data->
					        tl_data_length,
					    tl_data->tl_data_contents))
		    goto choke;
		else
		    outindex++;
	    }
	}

	/* Handle the key data */
	if (!is_set &&
	    ((valid  & KRB5_ADM_M_KEYDATA) != 0)) {
	    for (keyind = 0; keyind < dbentp->n_key_data; keyind++) {
		/*
		 * First handle kvno
		 */
		taglist[0] = (krb5_int32) keyind;
		taglist[1] = (krb5_int32) -1;
		taglist[2] = (krb5_int32) dbentp->key_data[keyind].
		    key_data_kvno;
		if (kret = format_kw_tagged(&outlist[outindex],
					    KRB5_ADM_KW_KEYDATA,
					    3,
					    taglist,
					    0,
					    (krb5_octet *) NULL))
		    goto choke;
		else
		    outindex++;

		/*
		 * Then each attribute as supported.
		 */
		for (attrind = 0;
		     attrind < KRB5_KDB_V1_KEY_DATA_ARRAY;
		     attrind++) {
		    taglist[1] = (krb5_int32) attrind;
		    taglist[2] = (krb5_int32) dbentp->key_data[keyind].
			key_data_type[attrind];
		    if (kret = format_kw_tagged(&outlist[outindex],
						KRB5_ADM_KW_KEYDATA,
						3,
						taglist,
						(krb5_int32) dbentp->
						    key_data[keyind].
						    key_data_length[attrind],
						dbentp->key_data[keyind].
						    key_data_contents[attrind])
			)
			goto choke;
		    else
			outindex++;
		}
	    }
	}

	/* Finally, handle the extra data */
	if ((valid & KRB5_ADM_M_EXTRADATA) != 0) {
	    if (kret = format_kw_tagged(&outlist[outindex],
					KRB5_ADM_KW_EXTRADATA,
					0,
					(krb5_int32 *) NULL,
					(krb5_int32) dbentp->e_length,
					dbentp->e_data))
		goto choke;
	    else
		outindex++;
	}
    }
    else {
	if (n2alloc)
	    kret = ENOMEM;
    }
 choke:
    if (kret) {
	if (outlist) {
	    int i;
	    for (i=0; i<outindex; i++) {
		if (outlist[i].data) {
		    memset(outlist[i].data, 0, (size_t) outlist[i].length);
		    free(outlist[i].data);
		}
	    }
	    free(outlist);
	}
	outlist = (krb5_data *) NULL;
	outindex = 0;
    }
    *datap = outlist;
    *nentp = outindex;
    return(kret);
}
#endif


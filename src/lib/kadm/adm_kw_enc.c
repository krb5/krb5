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
 * salt_type_to_string()	- Return a string for a given salt type.
 *
 * Add support for different salt types here.
 */
static char *
salt_type_to_string(stype)
    krb5_int32	stype;
{
    char	*retval = (char *) NULL;

    switch (stype) {
    case KRB5_KDB_SALTTYPE_NORMAL:
	retval = KRB5_ADM_SALTTYPE_NORMAL;  break;
    case KRB5_KDB_SALTTYPE_V4:
	retval = KRB5_ADM_SALTTYPE_V4;  break;
    case KRB5_KDB_SALTTYPE_NOREALM:
	retval = KRB5_ADM_SALTTYPE_NOREALM;  break;
    case KRB5_KDB_SALTTYPE_ONLYREALM:
	retval = KRB5_ADM_SALTTYPE_ONLYREALM;  break;
    case KRB5_KDB_SALTTYPE_SPECIAL:
	retval = KRB5_ADM_SALTTYPE_SPECIAL;  break;
    }
    return(retval);
}

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
	datap->data[datap->length]   = (char) ((val >> 24) & 0xff);
	datap->data[datap->length+1] = (char) ((val >> 16) & 0xff);
	datap->data[datap->length+2] = (char) ((val >> 8) & 0xff);
	datap->data[datap->length+3] = (char) (val & 0xff);
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
 * format_kw_salttype()	- Format a keyword=<salttype> pair.
 */
static krb5_error_code
format_kw_salttype(datap, kwordp, dbentp)
     krb5_data		*datap;
     char		*kwordp;
     krb5_db_entry	*dbentp;
{
    krb5_error_code	retval;
    char		fbuffer[BUFSIZ];
    char		*sstring;

    retval = EINVAL;
    sstring = salt_type_to_string(dbentp->salt_type);
    if (sstring) {
	strcpy(fbuffer, sstring);
	/* Only add secondary salt type if it's different and valid */
	if ((dbentp->salt_type != dbentp->alt_salt_type) &&
	    (sstring = salt_type_to_string(dbentp->alt_salt_type))) {
	    strcat(fbuffer,",");
	    strcat(fbuffer,sstring);
	}
	retval = format_kw_string(datap, kwordp, fbuffer);
    }
    return(retval);
}

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

    kret = 0;
    /* First check out whether this is a set or get and the mask */
    is_set = ((valid & KRB5_ADM_M_SET) == KRB5_ADM_M_SET);
    if ((is_set && ((valid & ~KRB5_ADM_M_SET_VALID) != 0)) ||
	(!is_set && ((valid & ~KRB5_ADM_M_GET_VALID) != 0)) ||
	(!is_set && ((valid & KRB5_ADM_M_GET) == 0)))
	return(EINVAL);

    /* Allocate a new array of output data */
    n2alloc = (is_set) ? KRB5_ADM_KW_MAX_SET : KRB5_ADM_KW_MAX_GET;
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
	/* Handle key version number */
	if ((valid & KRB5_ADM_M_KVNO) != 0) {
	    if (kret = format_kw_integer(&outlist[outindex],
					 KRB5_ADM_KW_KVNO,
					 (krb5_ui_4) dbentp->kvno))
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
	/* Handle salt types */
	if ((valid & KRB5_ADM_M_SALTTYPE) != 0) {
	    if (kret = format_kw_salttype(&outlist[outindex],
					  KRB5_ADM_KW_SALTTYPE,
					  dbentp))
		goto choke;
	    else
		outindex++;
	}
	/* Handle master key version number */
	if (!is_set &&
	    ((valid & KRB5_ADM_M_MKVNO) != 0)) {
	    if (kret = format_kw_integer(&outlist[outindex],
					 KRB5_ADM_KW_MKVNO,
					 (krb5_ui_4) dbentp->mkvno))
		goto choke;
	    else
		outindex++;
	}
	/* Handle last successful password change */
	if (!is_set &&
	    ((valid & KRB5_ADM_M_LASTPWCHANGE) != 0)) {
	    if (kret = format_kw_gentime(&outlist[outindex],
					 KRB5_ADM_KW_LASTPWCHANGE,
					 &dbentp->last_pwd_change))
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
	/* Handle last modification principal name */
	if (!is_set &&
	    ((valid & KRB5_ADM_M_MODNAME) != 0)) {
	    char *modifier_name;

	    /* Flatten the name, format it then free it. */
	    if (kret = krb5_unparse_name(kcontext,
					 dbentp->mod_name,
					 &modifier_name))
		goto choke;

	    kret = format_kw_string(&outlist[outindex],
				    KRB5_ADM_KW_MODNAME,
				    modifier_name);
	    krb5_xfree(modifier_name);
	    if (kret)
		goto choke;
	    else
		outindex++;
	}
	/* Handle last modification time */
	if (!is_set &&
	    ((valid & KRB5_ADM_M_MODDATE) != 0)) {
	    if (kret = format_kw_gentime(&outlist[outindex],
					 KRB5_ADM_KW_MODDATE,
					 &dbentp->mod_date))
		goto choke;
	    else
		outindex++;
	}
    }
    else
	kret = ENOMEM;
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


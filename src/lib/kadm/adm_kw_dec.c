/*
 * lib/kadm/adm_kw_dec.c
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
 * adm_kw_dec.c	- routines to decode keyword-value pairs.
 */
#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"

#define	char2int(c)	((c) - '0')

/*
 * keyword_value()	- Find index of keyword value if keyword is present.
 *
 * If a value is required, then the index of the keyword value is returned,
 * otherwise the index of the first character past the end of the keyword
 * string is returned.
 */
static off_t
keyword_value(dataentp, keyword, value_req)
    krb5_data		*dataentp;
    char		*keyword;
    krb5_boolean	value_req;
{
    off_t	len_req;

    len_req = strlen(keyword);
    if (value_req)
	len_req++;
    if ((dataentp->length >= len_req) &&
	(!strncmp(dataentp->data, keyword, strlen(keyword))) &&
	(!value_req || (dataentp->data[strlen(keyword)] == '=')))
	return(len_req);
    else
	return(-1);
}

/*
 * decode_kw_string()	- Decode a keyword=<string> pair and return the
 *			  string value if the pair is present.
 *
 * Note: successful callers must free the string storage.
 */
static krb5_error_code
decode_kw_string(dataentp, keyword, stringp)
    krb5_data	*dataentp;
    char	*keyword;
    char	**stringp;
{
    krb5_error_code	kret;
    off_t		valueoff;
    size_t		len2copy;

    kret = ENOENT;
    if ((valueoff = keyword_value(dataentp, keyword, 1)) >= 0) {
	kret = ENOMEM;
	len2copy = (size_t) ((off_t) dataentp->length - valueoff);
	*stringp = (char *) malloc(len2copy+1);
	if (*stringp) {
	    strncpy(*stringp, &dataentp->data[valueoff], len2copy);
	    (*stringp)[len2copy] = '\0';
	    kret = 0;
	}
    }
    return(kret);
}

/*
 * decode_kw_integer()	- Decode a keyword=<integer> pair and return the value
 *			  if the pair is present.
 */
static krb5_error_code
decode_kw_integer(dataentp, keyword, uintp)
    krb5_data	*dataentp;
    char	*keyword;
    krb5_ui_4	*uintp;
{
    krb5_error_code	kret;
    off_t		voff;
    size_t		len2copy;

    kret = ENOENT;
    if ((voff = keyword_value(dataentp, keyword, 1)) >= 0) {
	kret = EINVAL;
	len2copy = (size_t) ((off_t) dataentp->length - voff);
	if (len2copy == sizeof(krb5_ui_4)) {
	    *uintp = (((krb5_int32) ((unsigned char) dataentp->data[voff])
		       << 24) +
		      ((krb5_int32) ((unsigned char) dataentp->data[voff+1])
		       << 16) +
		      ((krb5_int32) ((unsigned char) dataentp->data[voff+2])
		       << 8) +
		      ((krb5_int32) ((unsigned char) dataentp->data[voff+3])));
	    kret = 0;
	}
    }
    return(kret);
}

/*
 * decode_kw_gentime()	- Decode a keyword=<general-time> pair and return the
 *			  time result if the pair is present.
 *
 * XXX - this knows too much about how Kerberos time is encoded.
 */
static krb5_error_code
decode_kw_gentime(dataentp, keyword, gtimep)
    krb5_data		*dataentp;
    char		*keyword;
    krb5_timestamp	*gtimep;
{
    krb5_error_code	kret;
    char		*timestring;
    struct tm		tval;
    time_t		temp_time;

    memset((char *) &tval, 0, sizeof(tval));
    timestring = (char *) NULL;
    if (!(kret = decode_kw_string(dataentp, keyword, &timestring))) {
	kret = EINVAL;
	if ((strlen(timestring) == 15) &&
	    (timestring[14] == 'Z')) {
	    tval.tm_year = 1000*char2int(timestring[0]) +
		100*char2int(timestring[1]) +
		    10*char2int(timestring[2]) +
			char2int(timestring[3]) - 1900;
	    tval.tm_mon = 10*char2int(timestring[4]) +
		char2int(timestring[5]) - 1;
	    tval.tm_mday = 10*char2int(timestring[6]) +
		char2int(timestring[7]);
	    tval.tm_hour = 10*char2int(timestring[8]) +
		char2int(timestring[9]);
	    tval.tm_min = 10*char2int(timestring[10]) +
		char2int(timestring[11]);
	    tval.tm_sec = 10*char2int(timestring[12]) +
		char2int(timestring[13]);
	    tval.tm_isdst = -1;
	    temp_time = gmt_mktime(&tval);
	    if (temp_time >= 0) {
		kret = 0;
		*gtimep = (krb5_timestamp) temp_time;
	    }
	}
	free(timestring);
    }
    return(kret);
}

/*
 * decode_kw_tagged()	- Decode a keyword=<taglist>...<data> list and return
 *			  the values of the tags and the data if the list is
 *			  present.
 */
static krb5_error_code
decode_kw_tagged(dataentp, keyword, ntags, taglist, lenp, datap)
    krb5_data		*dataentp;
    char		*keyword;
    krb5_int32		ntags;
    krb5_int32		*taglist;
    size_t		*lenp;
    krb5_octet		**datap;
{
    krb5_error_code	kret;
    off_t		valueoff;
    size_t		len2copy;
    unsigned char	*cp, *ep;
    int			i;

    kret = ENOENT;
    if ((valueoff = keyword_value(dataentp, keyword, 1)) >= 0) {
	/*
	 * Blast through the tags.
	 */
	kret = 0;
	cp = (unsigned char *) &dataentp->data[valueoff];
	ep = (unsigned char *) &dataentp->data[dataentp->length];
	for (i=0; i<ntags; i++) {
	    if (&cp[sizeof(krb5_int32)] > ep) {
		kret = EINVAL;
		break;
	    }
	    taglist[i] = (((krb5_int32) ((unsigned char) cp[0]) << 24) +
			  ((krb5_int32) ((unsigned char) cp[1]) << 16) +
			  ((krb5_int32) ((unsigned char) cp[2]) << 8) +
			  ((krb5_int32) ((unsigned char) cp[3])));
	    cp += sizeof(krb5_int32);
	}
	if (!kret) {
	    /*
	     * If we were successful, copy out the remaining bytes for value.
	     */
	    len2copy = (size_t) (ep - cp);
	    if (len2copy &&
		(*datap = (krb5_octet *) malloc(len2copy+1))) {
		memcpy(*datap, cp, len2copy);
		(*datap)[len2copy] = '\0';
	    }
	    if (len2copy && !*datap)
		kret = ENOMEM;
	    else
		*lenp = len2copy;
	}
    }
    return(kret);
}

#if ! defined(_WINDOWS) && ! defined(_MACINTOSH)
/*
 * krb5_adm_proto_to_dbent()	- Convert external attribute list into a
 *				  database entry.
 *
 * Scan through the keyword=value pairs in "data" until either the end of
 * the list (as determined from "nent") is reached, or an error occurs.
 * Return a mask of attributes which are set in "validp", the actual
 * attribute values in "dbentp" and "pwordp" if a password is specified.
 *
 * Successful callers must allocate the storage for "validp", "dbentp" and
 * must free the storage allocated for "pwordp" if a password is specified
 * and free the storage allocated for "validp->mod_name" if a modifier name
 * is specified.
 */
krb5_error_code
krb5_adm_proto_to_dbent(kcontext, nent, data, validp, dbentp, pwordp)
    krb5_context	kcontext;	/* Kerberos context	*/ /* In */
    krb5_int32		nent;		/* Number of components	*/ /* In */
    krb5_data		*data;		/* Component list	*/ /* In */
    krb5_ui_4		*validp;	/* Valid bitmask	*/ /* Out */
    krb5_db_entry	*dbentp;	/* Database entry	*/ /* Out */
    char		**pwordp;	/* Password string	*/ /* Out */
{
    int			i;
    krb5_error_code	retval;
    krb5_ui_4		parsed_mask;
    krb5_int32		taglist[4];
    size_t		data_length;
    krb5_octet		*tagged_data;
    struct key_tag_correlator {
	krb5_int32	key_tag;
	int		key_data_index;
    } *correlators, *correlation;
    int			ncorrelations;

    /* Initialize */
    retval = 0;
    parsed_mask = 0;
    *pwordp = (char *) NULL;
    correlators = (struct key_tag_correlator *) NULL;
    ncorrelations = 0;

    /* Loop through all the specified keyword=value pairs. */
    for (i=0; i<nent; i++) {
	/* Check for password */
	if (!(retval = decode_kw_string(&data[i],
					KRB5_ADM_KW_PASSWORD,
					pwordp))) {
	    parsed_mask |= KRB5_ADM_M_PASSWORD;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for maximum lifetime */
	if (!(retval = decode_kw_integer(&data[i],
					 KRB5_ADM_KW_MAXLIFE,
					 (krb5_ui_4 *) &dbentp->max_life))) {
	    parsed_mask |= KRB5_ADM_M_MAXLIFE;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for maximum renewable lifetime */
	if (!(retval = decode_kw_integer(&data[i],
					 KRB5_ADM_KW_MAXRENEWLIFE,
					 (krb5_ui_4 *)
					 &dbentp->max_renewable_life))) {
	    parsed_mask |= KRB5_ADM_M_MAXRENEWLIFE;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for principal expiration */
	if (!(retval = decode_kw_gentime(&data[i],
					 KRB5_ADM_KW_EXPIRATION,
					 &dbentp->expiration))) {
	    parsed_mask |= KRB5_ADM_M_EXPIRATION;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for password expiration */
	if (!(retval = decode_kw_gentime(&data[i],
					 KRB5_ADM_KW_PWEXPIRATION,
					 &dbentp->pw_expiration))) {
	    parsed_mask |= KRB5_ADM_M_PWEXPIRATION;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* random key - value optional */
	if (keyword_value(&data[i],
			  KRB5_ADM_KW_RANDOMKEY,
			  0) >= 0) {
	    krb5_ui_4	value;

	    if (retval = decode_kw_integer(&data[i],
					   KRB5_ADM_KW_RANDOMKEY,
					   &value)) {
		value = 1;
		retval = 0;
	    }
	    if (value)
		parsed_mask |= KRB5_ADM_M_RANDOMKEY;
	    else
		parsed_mask &= ~KRB5_ADM_M_RANDOMKEY;
	    continue;
	}

	/* Check for flags */
	if (!(retval = decode_kw_integer(&data[i],
					 KRB5_ADM_KW_FLAGS,
					 (krb5_ui_4 *) &dbentp->attributes))) {
	    parsed_mask |= KRB5_ADM_M_FLAGS;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for last successful password entry */
	if (!(retval = decode_kw_gentime(&data[i],
					 KRB5_ADM_KW_LASTSUCCESS,
					 &dbentp->last_success))) {
	    parsed_mask |= KRB5_ADM_M_LASTSUCCESS;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for last failed entry */
	if (!(retval = decode_kw_gentime(&data[i],
					 KRB5_ADM_KW_LASTFAILED,
					 &dbentp->last_failed))) {
	    parsed_mask |= KRB5_ADM_M_LASTFAILED;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for failure count */
	if (!(retval = decode_kw_integer(&data[i],
					 KRB5_ADM_KW_FAILCOUNT,
					 (krb5_ui_4 *)
					 &dbentp->fail_auth_count))) {
	    parsed_mask |= KRB5_ADM_M_FAILCOUNT;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for auxiliary data */
	if (!(retval = decode_kw_tagged(&data[i],
					KRB5_ADM_KW_AUXDATA,
					1,
					taglist,
					&data_length,
					&tagged_data))) {
	    krb5_tl_data	**fixupp;
	    krb5_tl_data	*tl_data, *new_tl;

	    /*
	     * We've got a tagged data value here.  We've got to do a little
	     * work to put it in the right place.  First, find the right place.
	     */
	    fixupp = &dbentp->tl_data;
	    for (tl_data = dbentp->tl_data;
		 tl_data; 
		 tl_data = tl_data->tl_data_next)
		fixupp = &tl_data->tl_data_next;

	    /* Get memory */
	    if (new_tl = (krb5_tl_data *) malloc(sizeof(krb5_tl_data))) {
		/* Fill in the supplied values */
		new_tl->tl_data_type = (krb5_int16) taglist[0];
		new_tl->tl_data_length = (krb5_int16) data_length;
		new_tl->tl_data_contents = tagged_data;

		/* Link in the right place */
		new_tl->tl_data_next= *fixupp;
		*fixupp = new_tl;

		/* Update counters and flags */
		dbentp->n_tl_data++;
		parsed_mask |= KRB5_ADM_M_AUXDATA;
	    }
	    else {
		retval = ENOMEM;
		break;
	    }
	    continue;
	}
	else {
	    if ((retval != ENOENT) && (retval != EINVAL))
		break;
	}

	/* Check for key data */
	if (!(retval = decode_kw_tagged(&data[i],
					KRB5_ADM_KW_KEYDATA,
					3,
					taglist,
					&data_length,
					&tagged_data))) {
	    krb5_boolean	corr_found;
	    int			cindex, kindex;
	    krb5_key_data	*kdata;

	    /*
	     * See if we already have a correlation betwen our key-tag and
	     * an index into the key table.
	     */
	    corr_found = 0;
	    for (cindex = 0; cindex < ncorrelations; cindex++) {
		if (correlators[cindex].key_tag == taglist[0]) {
		    correlation = &correlators[cindex];
		    corr_found = 1;
		    break;
		}
	    }

	    /* If not, then we had better make one up */
	    if (!corr_found) {
		/* Get a new list */
		if (correlation = (struct key_tag_correlator *)
		    malloc((ncorrelations+1)*
			   sizeof(struct key_tag_correlator))) {
		    /* Save the contents of the old one. */
		    if (ncorrelations) {
			memcpy(correlation, correlators,
			       ncorrelations*
			       sizeof(struct key_tag_correlator));
			/* Free the old one */
			free(correlators);
		    }
		    /* Point us at the new relation */
		    correlators = correlation;
		    correlation = &correlators[ncorrelations];
		    ncorrelations++;
		    correlation->key_tag = taglist[0];
		    /* Make a new key data entry */
		    if (kdata = (krb5_key_data *)
			malloc((dbentp->n_key_data+1)*sizeof(krb5_key_data))) {
			/* Copy the old list */
			if (dbentp->n_key_data) {
			    memcpy(kdata, dbentp->key_data,
				   dbentp->n_key_data*sizeof(krb5_key_data));
			    free(dbentp->key_data);
			}
			dbentp->key_data = kdata;
			correlation->key_data_index = dbentp->n_key_data;
			memset(&kdata[dbentp->n_key_data], 0,
			       sizeof(krb5_key_data));
			kdata[dbentp->n_key_data].key_data_ver = 1;
			dbentp->n_key_data++;
			corr_found = 1;
		    }
		    else
			retval = ENOMEM;
		}
		else
		    retval = ENOMEM;
	    }

	    /* Check to see if we either found a correlation or made one */
	    if (corr_found) {
		/* Special case for key version number */
		if (taglist[1] == -1) {
		    dbentp->key_data[correlation->key_data_index].
			key_data_kvno = taglist[2];
		}
		else {
		    dbentp->key_data[correlation->key_data_index].
			key_data_type[taglist[1]] = taglist[2];
		    dbentp->key_data[correlation->key_data_index].
			key_data_length[taglist[1]] = (krb5_int16) data_length;
		    dbentp->key_data[correlation->key_data_index].
			key_data_contents[taglist[1]] = tagged_data;
		}
		parsed_mask |= KRB5_ADM_M_KEYDATA;
	    }
	    else
		break;
	    continue;
	}
	else {
	    if ((retval != ENOENT) && (retval != EINVAL))
		break;
	}

	/* Check for extra data */
	if (!(retval = decode_kw_tagged(&data[i],
					KRB5_ADM_KW_EXTRADATA,
					0,
					taglist,
					&data_length,
					&dbentp->e_data))) {
	    dbentp->e_length = (krb5_int16) data_length;
	    parsed_mask |= KRB5_ADM_M_EXTRADATA;
	    continue;
	}
	else {
	    if ((retval != ENOENT) && (retval != EINVAL))
		break;
	}

	/* If we fall through here, we've got something unrecognized */
	if (retval) {
	    retval = EINVAL;
	    break;
	}
    }

    if (retval) {
	if (*pwordp) {
	    memset(*pwordp, 0, strlen(*pwordp));
	    free(*pwordp);
	    *pwordp = (char *) NULL;
	}
	parsed_mask = 0;
    }
    if (correlators)
	free(correlators);
    *validp |= parsed_mask;
    return(retval);
}
#endif

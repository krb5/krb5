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
 * string_to_salt_type()	- Convert from salt string to salt type.
 */
static krb5_int32
string_to_salt_type(sstring, retp)
    char		*sstring;
    krb5_error_code	*retp;
{
    krb5_error_code	kret;
    krb5_int32		stype;

    kret = EINVAL;
    stype = -1;
    if (!strcmp(sstring, KRB5_ADM_SALTTYPE_NORMAL))
	stype = KRB5_KDB_SALTTYPE_NORMAL;
    else if (!strcmp(sstring, KRB5_ADM_SALTTYPE_V4))
	stype = KRB5_KDB_SALTTYPE_V4;
    else if (!strcmp(sstring, KRB5_ADM_SALTTYPE_NOREALM))
	stype = KRB5_KDB_SALTTYPE_NOREALM;
    else if (!strcmp(sstring, KRB5_ADM_SALTTYPE_ONLYREALM))
	stype = KRB5_KDB_SALTTYPE_ONLYREALM;
    else if (!strcmp(sstring, KRB5_ADM_SALTTYPE_SPECIAL))
	stype = KRB5_KDB_SALTTYPE_SPECIAL;

    if (stype != -1)
	kret = 0;

    *retp = kret;
    return(stype);
}

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
 * decode_kw_salttype()	- Decode a keyword=<salttype> pair and fill in the
 *			  salt type values if the pair is present.
 */
static krb5_error_code
decode_kw_salttype(dataentp, keyword, dbentp)
    krb5_data		*dataentp;
    char		*keyword;
    krb5_db_entry	*dbentp;
{
    krb5_error_code	kret;
    char		*saltstring;
    char		*sentp;

    saltstring = (char *) NULL;
    if (!(kret = decode_kw_string(dataentp, keyword, &saltstring))) {
	kret = EINVAL;
	if (sentp = strchr(saltstring, (int) ',')) {
	    *sentp = '\0';
	    sentp++;
	}
	dbentp->salt_type = string_to_salt_type(saltstring, &kret);
	if (!kret && sentp) {
	    dbentp->alt_salt_type = string_to_salt_type(sentp, &kret);
	}
	free(saltstring);
    }
    return(kret);
}

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
    char		*modifier_name;

    /* Initialize */
    retval = 0;
    parsed_mask = 0;
    *pwordp = (char *) NULL;

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

	/* Check for key version number */
	if (!(retval = decode_kw_integer(&data[i],
					 KRB5_ADM_KW_KVNO,
					 (krb5_ui_4 *) &dbentp->kvno))) {
	    parsed_mask |= KRB5_ADM_M_KVNO;
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

	/* Check for salttype */
	if (!(retval = decode_kw_salttype(&data[i],
					  KRB5_ADM_KW_SALTTYPE,
					  dbentp))) {
	    parsed_mask |= KRB5_ADM_M_SALTTYPE;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for master key version number */
	if (!(retval = decode_kw_integer(&data[i],
					 KRB5_ADM_KW_MKVNO,
					 (krb5_ui_4 *) &dbentp->mkvno))) {
	    parsed_mask |= KRB5_ADM_M_MKVNO;
	    continue;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for last password change */
	if (!(retval = decode_kw_gentime(&data[i],
					 KRB5_ADM_KW_LASTPWCHANGE,
					 &dbentp->last_pwd_change))) {
	    parsed_mask |= KRB5_ADM_M_LASTPWCHANGE;
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

	/* Check for modification principal */
	if (!(retval = decode_kw_string(&data[i],
					KRB5_ADM_KW_MODNAME,
					&modifier_name))) {
	    krb5_principal	modifier;
	    retval = krb5_parse_name(kcontext, modifier_name, &modifier);
	    free(modifier_name);
	    if (!retval) {
		if (dbentp->mod_name)
		    krb5_free_principal(kcontext, dbentp->mod_name);
		dbentp->mod_name = modifier;
		parsed_mask |= KRB5_ADM_M_MODNAME;
		continue;
	    }
	    else
		break;
	}
	else {
	    if (retval != ENOENT)
		break;
	}

	/* Check for modification time */
	if (!(retval = decode_kw_gentime(&data[i],
					 KRB5_ADM_KW_MODDATE,
					 &dbentp->mod_date))) {
	    parsed_mask |= KRB5_ADM_M_MODDATE;
	    continue;
	}
	else {
	    if (retval != ENOENT)
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
    *validp |= parsed_mask;
    return(retval);
}

/*
 * lib/kadm/alt_prof.c
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
 * alt_prof.c - Implement alternate profile file handling.
 */
#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"
#include <stdio.h>

/*
 * krb5_aprof_init()	- Initialize alternate profile context.
 *
 * Parameters:
 *	fname		- default file name of the profile.
 *	envname		- environment variable name which can override fname.
 *	acontextp	- Pointer to opaque context for alternate profile.
 *
 * Returns:
 *	error codes from profile_init()
 */
krb5_error_code
krb5_aprof_init(fname, envname, acontextp)
    char		*fname;
    char		*envname;
    krb5_pointer	*acontextp;
{
    krb5_error_code	kret;
    const char		*namelist[2];
    profile_t		profile;
    
    namelist[1] = (char *) NULL;
    profile = (profile_t) NULL;
    if (envname) {
	if (namelist[0] = getenv(envname)) {
	    if (!(kret = profile_init(namelist, &profile))) {
		*acontextp = (krb5_pointer) profile;
		return(0);
	    }
	}
    }
    namelist[0] = fname;
    profile = (profile_t) NULL;
    if (!(kret = profile_init(namelist, &profile))) {
	*acontextp = (krb5_pointer) profile;
	return(0);
    }
    return(kret);
}

/*
 * krb5_aprof_getvals()	- Get values from alternate profile.
 *
 * Parameters:
 *	acontext	- opaque context for alternate profile.
 *	hierarchy	- hierarchy of value to retrieve.
 *	retdata		- Returned data values.
 *
 * Returns:
 * 	error codes from profile_get_values()
 */
krb5_error_code
krb5_aprof_getvals(acontext, hierarchy, retdata)
    krb5_pointer	acontext;
    const char		**hierarchy;
    char		***retdata;
{
    return(profile_get_values((profile_t) acontext,
			      hierarchy,
			      retdata));
}

/*
 * krb5_aprof_get_deltat()	- Get a delta time value from the alternate
 *				  profile.
 *
 * Parameters:
 *	acontext		- opaque context for alternate profile.
 *	hierarchy		- hierarchy of value to retrieve.
 *	uselast			- if true, use last value, otherwise use
 *				  first value found.
 *	deltatp			- returned delta time value.
 *
 * Returns:
 * 	error codes from profile_get_values()
 *	error codes from krb5_string_to_deltat()
 */
krb5_error_code
krb5_aprof_get_deltat(acontext, hierarchy, uselast, deltatp)
    krb5_pointer	acontext;
    const char		**hierarchy;
    krb5_boolean	uselast;
    krb5_deltat		*deltatp;
{
    krb5_error_code	kret;
    char		**values;
    char		*valp;
    int			index;

    if (!(kret = krb5_aprof_getvals(acontext, hierarchy, &values))) {
	index = 0;
	if (uselast) {
	    for (index=0; values[index]; index++);
	    index--;
	}
	valp = values[index];
	kret = krb5_string_to_deltat(valp, deltatp);

	/* Free the string storage */
	for (index=0; values[index]; index++)
	    krb5_xfree(values[index]);
	krb5_xfree(values);
    }
    return(kret);
}

/*
 * krb5_aprof_get_string()	- Get a string value from the alternate
 *				  profile.
 *
 * Parameters:
 *	acontext		- opaque context for alternate profile.
 *	hierarchy		- hierarchy of value to retrieve.
 *	uselast			- if true, use last value, otherwise use
 *				  first value found.
 *	stringp			- returned string value.
 *
 * Returns:
 * 	error codes from profile_get_values()
 */
krb5_error_code
krb5_aprof_get_string(acontext, hierarchy, uselast, stringp)
    krb5_pointer	acontext;
    const char		**hierarchy;
    krb5_boolean	uselast;
    char		**stringp;
{
    krb5_error_code	kret;
    char		**values;
    int			index, i;

    if (!(kret = krb5_aprof_getvals(acontext, hierarchy, &values))) {
	index = 0;
	if (uselast) {
	    for (index=0; values[index]; index++);
	    index--;
	}

	*stringp = values[index];

	/* Free the string storage */
	for (i=0; values[i]; i++)
	    if (i != index)
		krb5_xfree(values[i]);
	krb5_xfree(values);
    }
    return(kret);
}

/*
 * krb5_aprof_get_int32()	- Get a 32-bit integer value from the alternate
 *				  profile.
 *
 * Parameters:
 *	acontext		- opaque context for alternate profile.
 *	hierarchy		- hierarchy of value to retrieve.
 *	uselast			- if true, use last value, otherwise use
 *				  first value found.
 *	intp			- returned 32-bit integer value.
 *
 * Returns:
 * 	error codes from profile_get_values()
 *	EINVAL			- value is not an integer
 */
krb5_error_code
krb5_aprof_get_int32(acontext, hierarchy, uselast, intp)
    krb5_pointer	acontext;
    const char		**hierarchy;
    krb5_boolean	uselast;
    krb5_int32		*intp;
{
    krb5_error_code	kret;
    char		**values;
    int			index;

    if (!(kret = krb5_aprof_getvals(acontext, hierarchy, &values))) {
	index = 0;
	if (uselast) {
	    for (index=0; values[index]; index++);
	    index--;
	}

	if (sscanf(values[index], "%d", intp) != 1)
	    kret = EINVAL;

	/* Free the string storage */
	for (index=0; values[index]; index++)
	    krb5_xfree(values[index]);
	krb5_xfree(values);
    }
    return(kret);
}

/*
 * krb5_aprof_finish()	- Finish alternate profile context.
 *
 * Parameter:
 *	acontext	- opaque context for alternate profile.
 *
 * Returns:
 *	0 on success, something else on failure.
 */
krb5_error_code
krb5_aprof_finish(acontext)
    krb5_pointer	acontext;
{
    profile_release(acontext);
}

/*
 * krb5_read_realm_params()	- Read per-realm parameters from KDC
 *				  alternate profile.
 */
krb5_error_code
krb5_read_realm_params(kcontext, realm, kdcprofile, kdcenv, rparamp)
    krb5_context	kcontext;
    char		*realm;
    char		*kdcprofile;
    char		*kdcenv;
    krb5_realm_params	**rparamp;
{
    char		*filename;
    char		*envname;
    char		*lrealm;
    krb5_pointer	aprofile;
    krb5_realm_params	*rparams;
    const char		*hierarchy[4];
    char		*svalue;
    krb5_int32		ivalue;
    krb5_deltat		dtvalue;

    krb5_error_code	kret;

    filename = (kdcprofile) ? kdcprofile : DEFAULT_KDC_PROFILE;
    envname = (kdcenv) ? kdcenv : KDC_PROFILE_ENV;
    rparams = (krb5_realm_params *) NULL;
    kret = 0;
    if (!realm)
	kret = krb5_get_default_realm(kcontext, &lrealm);
    else
	lrealm = strdup(realm);
    if (!kret && !(kret = krb5_aprof_init(filename, envname, &aprofile))) {
	if (rparams =
	    (krb5_realm_params *) malloc(sizeof(krb5_realm_params))) {

	    /* Initialize realm parameters */
	    memset((char *) rparams, 0, sizeof(krb5_realm_params));

	    /* Get the value of the per-realm profile */
	    hierarchy[0] = "realms";
	    hierarchy[1] = lrealm;
	    hierarchy[2] = "profile";
	    hierarchy[3] = (char *) NULL;
	    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
		const char *filenames[2];

		/*
		 * XXX this knows too much about krb5 contexts.
		 */
		filenames[0] = svalue;
		filenames[1] = (char *) NULL;
		if (kcontext->profile)
		    profile_release(kcontext->profile);
		if (!(kret = profile_init(filenames, &kcontext->profile)))
		    rparams->realm_profile = svalue;
		else
		    krb5_xfree(svalue);
	    }

	    /* Get the value for the database */
	    hierarchy[2] = "database_name";
	    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue))
		rparams->realm_dbname = svalue;

	    /* Get the value for the KDC primary port */
	    hierarchy[2] = "port";
	    if (!krb5_aprof_get_int32(aprofile, hierarchy, TRUE, &ivalue)) {
		rparams->realm_kdc_pport = ivalue;
		rparams->realm_kdc_pport_valid = 1;
	    }
	    
	    /* Get the value for the KDC secondary port */
	    hierarchy[2] = "secondary_port";
	    if (!krb5_aprof_get_int32(aprofile, hierarchy, TRUE, &ivalue)) {
		rparams->realm_kdc_sport = ivalue;
		rparams->realm_kdc_sport_valid = 1;
	    }
	    
	    /* Get the value for the kadmind port */
	    hierarchy[2] = "kadmind_port";
	    if (!krb5_aprof_get_int32(aprofile, hierarchy, TRUE, &ivalue)) {
		rparams->realm_kadmind_port = ivalue;
		rparams->realm_kadmind_port_valid = 1;
	    }
	    
	    /* Get the value for the master key name */
	    hierarchy[2] = "master_key_name";
	    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue))
		rparams->realm_mkey_name = svalue;
	    
	    /* Get the value for the master key type */
	    hierarchy[2] = "master_key_type";
	    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
		if (!krb5_string_to_keytype(svalue, &rparams->realm_keytype))
		    rparams->realm_keytype_valid = 1;
		krb5_xfree(svalue);
	    }
	    
	    /* Get the value for the encryption type */
	    hierarchy[2] = "encryption_type";
	    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
		if (!krb5_string_to_enctype(svalue, &rparams->realm_enctype))
		    rparams->realm_enctype_valid = 1;
		krb5_xfree(svalue);
	    }
	    
	    /* Get the value for the stashfile */
	    hierarchy[2] = "key_stash_file";
	    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue))
		rparams->realm_stash_file = svalue;
	    
	    /* Get the value for maximum ticket lifetime. */
	    hierarchy[2] = "max_life";
	    if (!krb5_aprof_get_deltat(aprofile, hierarchy, TRUE, &dtvalue)) {
		rparams->realm_max_life = dtvalue;
		rparams->realm_max_life_valid = 1;
	    }
	    
	    /* Get the value for maximum renewable ticket lifetime. */
	    hierarchy[2] = "max_renewable_life";
	    if (!krb5_aprof_get_deltat(aprofile, hierarchy, TRUE, &dtvalue)) {
		rparams->realm_max_rlife = dtvalue;
		rparams->realm_max_rlife_valid = 1;
	    }
	    
	    /* Get the value for the default principal expiration */
	    hierarchy[2] = "default_principal_expiration";
	    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
		if (!krb5_string_to_timestamp(svalue,
					      &rparams->realm_expiration))
		    rparams->realm_expiration_valid = 1;
		krb5_xfree(svalue);
	    }
	    
	    /* Get the value for the default principal flags */
	    hierarchy[2] = "default_principal_flags";
	    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
		char *sp, *ep, *tp;

		sp = svalue;
		rparams->realm_flags = 0;
		while (sp) {
		    if ((ep = strchr(sp, (int) ',')) ||
			(ep = strchr(sp, (int) ' ')) ||
			(ep = strchr(sp, (int) '\t'))) {
			/* Fill in trailing whitespace of sp */
			tp = ep - 1;
			while (isspace(*tp) && (tp < sp)) {
			    *tp = '\0';
			    tp--;
			}
			*ep = '\0';
			ep++;
			/* Skip over trailing whitespace of ep */
			while (isspace(*ep) && (*ep)) ep++;
		    }
		    /* Convert this flag */
		    if (krb5_string_to_flags(sp,
					     "+",
					     "-",
					     &rparams->realm_flags))
			break;
		    sp = ep;
		}
		if (!sp)
		    rparams->realm_flags_valid = 1;
		krb5_xfree(svalue);
	    }

	    /* Get the value for the supported keytype/salttype matrix */
	    hierarchy[2] = "supported_keytypes";
	    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
		krb5_string_to_keysalts(svalue,
					", \t",	/* Tuple separators	*/
					":.-",	/* Key/salt separators	*/
					0,	/* No duplicates	*/
					&rparams->realm_keysalts,
					&rparams->realm_num_keysalts);
		krb5_xfree(svalue);
	    }
	}
	krb5_aprof_finish(aprofile);
    }
    *rparamp = rparams;
    return(kret);
}

/*
 * krb5_free_realm_params()	- Free data allocated by above.
 */
krb5_error_code
krb5_free_realm_params(kcontext, rparams)
    krb5_context	kcontext;
    krb5_realm_params	*rparams;
{
    if (rparams) {
	if (rparams->realm_profile)
	    krb5_xfree(rparams->realm_profile);
	if (rparams->realm_dbname)
	    krb5_xfree(rparams->realm_dbname);
	if (rparams->realm_mkey_name)
	    krb5_xfree(rparams->realm_mkey_name);
	if (rparams->realm_stash_file)
	    krb5_xfree(rparams->realm_stash_file);
	if (rparams->realm_keysalts)
	    krb5_xfree(rparams->realm_keysalts);
	krb5_xfree(rparams);
    }
    return(0);
}


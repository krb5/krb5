/*
 * lib/kadm/alt_prof.c
 *
 * Copyright 1995,2001,2008 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * alt_prof.c - Implement alternate profile file handling.
 */
#include "k5-int.h"
#include <kadm5/admin.h>
#include "adm_proto.h"
#include <stdio.h>
#include <ctype.h>
#include <kdb_log.h>

static krb5_key_salt_tuple *copy_key_salt_tuple(ksalt, len)
krb5_key_salt_tuple *ksalt;
krb5_int32 len;
{
    krb5_key_salt_tuple *knew;    

    if((knew = (krb5_key_salt_tuple *)
		malloc((len ) * sizeof(krb5_key_salt_tuple)))) {
         memcpy(knew, ksalt, len * sizeof(krb5_key_salt_tuple));
	 return knew;
    }
    return 0;
}

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
    profile_t		profile;
    const char *kdc_config;
    char *profile_path;
    char **filenames;
    int i;
    struct k5buf buf;

    kret = krb5_get_default_config_files (&filenames);
    if (kret)
	return kret;
    if (envname == NULL || (kdc_config = getenv(envname)) == NULL)
	kdc_config = fname;
    krb5int_buf_init_dynamic(&buf);
    if (kdc_config)
	krb5int_buf_add(&buf, kdc_config);
    for (i = 0; filenames[i] != NULL; i++) {
	if (krb5int_buf_len(&buf) > 0)
	    krb5int_buf_add(&buf, ":");
	krb5int_buf_add(&buf, filenames[i]);
    }
    krb5_free_config_files(filenames);
    profile_path = krb5int_buf_data(&buf);
    if (profile_path == NULL)
	return ENOMEM;
    profile = (profile_t) NULL;
    kret = profile_init_path(profile_path, &profile);
    free(profile_path);
    if (kret)
	return kret;
    *acontextp = profile;
    return 0;
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
 * krb5_aprof_get_boolean()
 *
 * Parameters:
 *	acontext	- opaque context for alternate profile
 *	hierarchy	- hierarchy of value to retrieve
 *	retdata		- Returned data value
 * Returns:
 *	error codes
 */

static krb5_error_code
string_to_boolean (const char *string, krb5_boolean *out)
{
    static const char *const yes[] = { "y", "yes", "true", "t", "1", "on" };
    static const char *const no[] = { "n", "no", "false", "f", "nil", "0", "off" };
    int i;

    for (i = 0; i < sizeof(yes)/sizeof(yes[0]); i++)
	if (!strcasecmp(string, yes[i])) {
	    *out = 1;
	    return 0;
	}
    for (i = 0; i < sizeof(no)/sizeof(no[0]); i++)
	if (!strcasecmp(string, no[i])) {
	    *out = 0;
	    return 0;
	}
    return PROF_BAD_BOOLEAN;
}

krb5_error_code
krb5_aprof_get_boolean(krb5_pointer acontext, const char **hierarchy,
		       int uselast, krb5_boolean *retdata)
{
    krb5_error_code kret;
    char **values;
    char *valp;
    int idx;
    krb5_boolean val;

    kret = krb5_aprof_getvals (acontext, hierarchy, &values);
    if (kret)
	return kret;
    idx = 0;
    if (uselast) {
	while (values[idx])
	    idx++;
	idx--;
    }
    valp = values[idx];
    kret = string_to_boolean (valp, &val);
    if (kret)
	return kret;
    *retdata = val;
    return 0;
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
    int			idx;

    if (!(kret = krb5_aprof_getvals(acontext, hierarchy, &values))) {
	idx = 0;
	if (uselast) {
	    for (idx=0; values[idx]; idx++);
	    idx--;
	}
	valp = values[idx];
	kret = krb5_string_to_deltat(valp, deltatp);

	/* Free the string storage */
	for (idx=0; values[idx]; idx++)
	    krb5_xfree(values[idx]);
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
    int			idx, i;

    if (!(kret = krb5_aprof_getvals(acontext, hierarchy, &values))) {
	idx = 0;
	if (uselast) {
	    for (idx=0; values[idx]; idx++);
	    idx--;
	}

	*stringp = values[idx];

	/* Free the string storage */
	for (i=0; values[i]; i++)
	    if (i != idx)
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
    int			idx;

    if (!(kret = krb5_aprof_getvals(acontext, hierarchy, &values))) {
	idx = 0;
	if (uselast) {
	    for (idx=0; values[idx]; idx++);
	    idx--;
	}

	if (sscanf(values[idx], "%d", intp) != 1)
	    kret = EINVAL;

	/* Free the string storage */
	for (idx=0; values[idx]; idx++)
	    krb5_xfree(values[idx]);
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
    return(0);
}

/*
 * Returns nonzero if it found something to copy; the caller may still
 * need to check the output field or mask to see if the copy
 * (allocation) was successful.  Returns zero if nothing was found to
 * copy, and thus the caller may want to apply some default heuristic.
 * If the default action is just to use a fixed, compiled-in string,
 * supply it as the default value here and ignore the return value.
 */
static int
get_string_param(char **param_out, char *param_in,
		 long *mask_out, long mask_in, long mask_bit,
		 krb5_pointer aprofile,
		 const char **hierarchy,
		 const char *config_name,
		 const char *default_value)
{
    char *svalue;

    hierarchy[2] = config_name;
    if (mask_in & mask_bit) {
	*param_out = strdup(param_in);
	if (*param_out)
	    *mask_out |= mask_bit;
	return 1;
    } else if (aprofile &&
	       !krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
	*param_out = svalue;
	*mask_out |= mask_bit;
	return 1;
    } else if (default_value) {
	*param_out = strdup(default_value);
	if (*param_out)
	    *mask_out |= mask_bit;
	return 1;
    } else {
	return 0;
    }
}
/*
 * Similar, for (host-order) port number, if not already set in the
 * output field; default_value==0 means no default.
 */
static void
get_port_param(int *param_out, int param_in,
	       long *mask_out, long mask_in, long mask_bit,
	       krb5_pointer aprofile,
	       const char **hierarchy,
	       const char *config_name,
	       int default_value)
{
    krb5_int32 ivalue;

    if (! (*mask_out & mask_bit)) {
	hierarchy[2] = config_name;
	if (mask_in & mask_bit) {
	    *mask_out |= mask_bit;
	    *param_out = param_in;
	} else if (aprofile &&
		   !krb5_aprof_get_int32(aprofile, hierarchy, TRUE, &ivalue)) {
	    *param_out = ivalue;
	    *mask_out |= mask_bit;
	} else if (default_value) {
	    *param_out = default_value;
	    *mask_out |= mask_bit;
	}
    }
}
/*
 * Similar, for delta_t; default is required.
 */
static void
get_deltat_param(krb5_deltat *param_out, krb5_deltat param_in,
		 long *mask_out, long mask_in, long mask_bit,
		 krb5_pointer aprofile,
		 const char **hierarchy,
		 const char *config_name,
		 krb5_deltat default_value)
{
    krb5_deltat dtvalue;

    hierarchy[2] = config_name;
    if (mask_in & mask_bit) {
	*mask_out |= mask_bit;
	*param_out = param_in;
    } else if (aprofile &&
	       !krb5_aprof_get_deltat(aprofile, hierarchy, TRUE, &dtvalue)) {
	*param_out = dtvalue;
	*mask_out |= mask_bit;
    } else {
	*param_out = default_value;
	*mask_out |= mask_bit;
    }
}

/*
 * Function: kadm5_get_config_params
 *
 * Purpose: Merge configuration parameters provided by the caller with
 * values specified in configuration files and with default values.
 *
 * Arguments:
 *
 *	context		(r) krb5_context to use
 *	profile		(r) profile file to use
 *	envname		(r) envname that contains a profile name to
 *			override profile
 *	params_in	(r) params structure containing user-supplied
 *			values, or NULL
 *	params_out	(w) params structure to be filled in
 *
 * Effects:
 *
 * The fields and mask of params_out are filled in with values
 * obtained from params_in, the specified profile, and default
 * values.  Only and all fields specified in params_out->mask are
 * set.  The context of params_out must be freed with
 * kadm5_free_config_params.
 *
 * params_in and params_out may be the same pointer.  However, all pointers
 * in params_in for which the mask is set will be re-assigned to newly copied
 * versions, overwriting the old pointer value.
 */
krb5_error_code kadm5_get_config_params(context, use_kdc_config,
					params_in, params_out)
   krb5_context		context;
   int			use_kdc_config;
   kadm5_config_params	*params_in, *params_out;
{
    char		*filename;
    char		*envname;
    char		*lrealm;
    krb5_pointer	aprofile = 0;
    const char		*hierarchy[4];
    char		*svalue;
    krb5_int32		ivalue;
    kadm5_config_params params, empty_params;

    krb5_error_code	kret = 0;

    memset((char *) &params, 0, sizeof(params));
    memset((char *) &empty_params, 0, sizeof(empty_params));

    if (params_in == NULL) params_in = &empty_params;

    if (params_in->mask & KADM5_CONFIG_REALM) {
	 lrealm = params.realm = strdup(params_in->realm);
	 if (params.realm)
	      params.mask |= KADM5_CONFIG_REALM;
    } else {
	 kret = krb5_get_default_realm(context, &lrealm);
	 if (kret)
	      goto cleanup;
	 params.realm = lrealm;
	 params.mask |= KADM5_CONFIG_REALM;
    }

    if (params_in->mask & KADM5_CONFIG_KVNO) {
        params.kvno = params_in->kvno;
        params.mask |= KADM5_CONFIG_KVNO;
    }
    /*
     * XXX These defaults should to work on both client and
     * server.  kadm5_get_config_params can be implemented as a
     * wrapper function in each library that provides correct
     * defaults for NULL values.
     */
    if (use_kdc_config) {
	filename = DEFAULT_KDC_PROFILE;
	envname = KDC_PROFILE_ENV;
    } else {
	filename = DEFAULT_PROFILE_PATH;
	envname = "KRB5_CONFIG";
    }
    if (context->profile_secure == TRUE) envname = 0;

    kret = krb5_aprof_init(filename, envname, &aprofile);
    if (kret)
	    goto cleanup;
    
    /* Initialize realm parameters */
    hierarchy[0] = "realms";
    hierarchy[1] = lrealm;
    hierarchy[3] = (char *) NULL;

#define GET_STRING_PARAM(FIELD, BIT, CONFTAG, DEFAULT)		\
    get_string_param(&params.FIELD, params_in->FIELD,		\
		     &params.mask, params_in->mask, BIT,	\
		     aprofile, hierarchy, CONFTAG, DEFAULT)

    /* Get the value for the admin server */
    GET_STRING_PARAM(admin_server, KADM5_CONFIG_ADMIN_SERVER, "admin_server",
		     NULL);

    if (params.mask & KADM5_CONFIG_ADMIN_SERVER) {
	 char *p;
	 p = strchr(params.admin_server, ':');
	 if (p) {
	      params.kadmind_port = atoi(p+1);
	      params.mask |= KADM5_CONFIG_KADMIND_PORT;
	      *p = '\0';
	 }
    }

    /* Get the value for the database */
    GET_STRING_PARAM(dbname, KADM5_CONFIG_DBNAME, "database_name",
		     DEFAULT_KDB_FILE);

    params.admin_dbname_was_here = NULL;
    params.admin_lockfile_was_here = NULL;
    /* never set KADM5_CONFIG_ADBNAME, KADM5_CONFIG_ADB_LOCKFILE */

    /* Get the value for the admin (policy) database lock file*/
    if (!GET_STRING_PARAM(admin_keytab, KADM5_CONFIG_ADMIN_KEYTAB,
			  "admin_keytab", NULL)) {
	const char *s = getenv("KRB5_KTNAME");
	if (s == NULL)
	    s = DEFAULT_KADM5_KEYTAB;
	params.admin_keytab = strdup(s);
	if (params.admin_keytab)
	    params.mask |= KADM5_CONFIG_ADMIN_KEYTAB;
    }
    
    /* Get the name of the acl file */
    GET_STRING_PARAM(acl_file, KADM5_CONFIG_ACL_FILE, "acl_file",
		     DEFAULT_KADM5_ACL_FILE);

    /* Get the name of the dict file */
    GET_STRING_PARAM(dict_file, KADM5_CONFIG_DICT_FILE, "dict_file", NULL);

#define GET_PORT_PARAM(FIELD, BIT, CONFTAG, DEFAULT)		\
    get_port_param(&params.FIELD, params_in->FIELD,		\
		   &params.mask, params_in->mask, BIT,		\
		   aprofile, hierarchy, CONFTAG, DEFAULT)
    /* Get the value for the kadmind port */
    GET_PORT_PARAM(kadmind_port, KADM5_CONFIG_KADMIND_PORT,
		   "kadmind_port", DEFAULT_KADM5_PORT);

    /* Get the value for the kpasswd port */
    GET_PORT_PARAM(kpasswd_port, KADM5_CONFIG_KPASSWD_PORT,
		   "kpasswd_port", DEFAULT_KPASSWD_PORT);

    /* Get the value for the master key name */
    GET_STRING_PARAM(mkey_name, KADM5_CONFIG_MKEY_NAME,
		     "master_key_name", NULL);

    /* Get the value for the master key type */
    hierarchy[2] = "master_key_type";
    if (params_in->mask & KADM5_CONFIG_ENCTYPE) {
	 params.mask |= KADM5_CONFIG_ENCTYPE;
	 params.enctype = params_in->enctype;
    } else if (aprofile &&
	       !krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
	 if (!krb5_string_to_enctype(svalue, &params.enctype)) {
	      params.mask |= KADM5_CONFIG_ENCTYPE;
	      krb5_xfree(svalue);
	 }
    } else {
	 params.mask |= KADM5_CONFIG_ENCTYPE;
	 params.enctype = DEFAULT_KDC_ENCTYPE;
    }
    
    /* Get the value for mkey_from_kbd */
    if (params_in->mask & KADM5_CONFIG_MKEY_FROM_KBD) {
	 params.mask |= KADM5_CONFIG_MKEY_FROM_KBD;
	 params.mkey_from_kbd = params_in->mkey_from_kbd;
    }
    
    /* Get the value for the stashfile */
    GET_STRING_PARAM(stash_file, KADM5_CONFIG_STASH_FILE,
		     "key_stash_file", NULL);

    /* Get the value for maximum ticket lifetime. */
#define GET_DELTAT_PARAM(FIELD, BIT, CONFTAG, DEFAULT)		\
    get_deltat_param(&params.FIELD, params_in->FIELD,		\
		     &params.mask, params_in->mask, BIT,	\
		     aprofile, hierarchy, CONFTAG, DEFAULT)

    GET_DELTAT_PARAM(max_life, KADM5_CONFIG_MAX_LIFE, "max_life",
		     24 * 60 * 60); /* 1 day */

    /* Get the value for maximum renewable ticket lifetime. */
    GET_DELTAT_PARAM(max_rlife, KADM5_CONFIG_MAX_RLIFE, "max_renewable_life",
		     0);

    /* Get the value for the default principal expiration */
    hierarchy[2] = "default_principal_expiration";
    if (params_in->mask & KADM5_CONFIG_EXPIRATION) {
	 params.mask |= KADM5_CONFIG_EXPIRATION;
	 params.expiration = params_in->expiration;
    } else if (aprofile &&
	       !krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
	 if (!krb5_string_to_timestamp(svalue, &params.expiration)) {
	      params.mask |= KADM5_CONFIG_EXPIRATION;
	      krb5_xfree(svalue);
	 }
    } else {
	 params.mask |= KADM5_CONFIG_EXPIRATION;
	 params.expiration = 0;
    }
    
    /* Get the value for the default principal flags */
    hierarchy[2] = "default_principal_flags";
    if (params_in->mask & KADM5_CONFIG_FLAGS) {
	 params.mask |= KADM5_CONFIG_FLAGS;
	 params.flags = params_in->flags;
    } else if (aprofile &&
	       !krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue)) {
	 char *sp, *ep, *tp;
	 
	 sp = svalue;
	 params.flags = 0;
	 while (sp) {
	      if ((ep = strchr(sp, (int) ',')) ||
		  (ep = strchr(sp, (int) ' ')) ||
		  (ep = strchr(sp, (int) '\t'))) {
		   /* Fill in trailing whitespace of sp */
		   tp = ep - 1;
		   while (isspace((int) *tp) && (tp > sp)) {
			*tp = '\0';
			tp--;
		   }
		   *ep = '\0';
		   ep++;
		   /* Skip over trailing whitespace of ep */
		   while (isspace((int) *ep) && (*ep)) ep++;
	      }
	      /* Convert this flag */
	      if (krb5_string_to_flags(sp,
				       "+",
				       "-",
				       &params.flags))
		   break;
	      sp = ep;
	 }
	 if (!sp)
	      params.mask |= KADM5_CONFIG_FLAGS;
	 krb5_xfree(svalue);
    } else {
	 params.mask |= KADM5_CONFIG_FLAGS;
	 params.flags = KRB5_KDB_DEF_FLAGS;
    }

    /* Get the value for the supported enctype/salttype matrix */
    hierarchy[2] = "supported_enctypes";
    if (params_in->mask & KADM5_CONFIG_ENCTYPES) {
         /* The following scenario is when the input keysalts are !NULL */
         if(params_in->keysalts) {
	       params.keysalts = copy_key_salt_tuple(params_in->keysalts, 
						     params_in->num_keysalts);
	       if(params.keysalts) {
		 params.mask |= KADM5_CONFIG_ENCTYPES;
		 params.num_keysalts = params_in->num_keysalts;
	       }
	 } else {
		 params.mask |= KADM5_CONFIG_ENCTYPES;
		 params.keysalts = 0;
		 params.num_keysalts = params_in->num_keysalts;
	 }
    } else {
	 svalue = NULL;
	 if (aprofile)
	      krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue);
	 if (svalue == NULL)
	     svalue = strdup("des3-hmac-sha1:normal des-cbc-crc:normal");

	 params.keysalts = NULL;
	 params.num_keysalts = 0;
	 krb5_string_to_keysalts(svalue,
				 ", \t",/* Tuple separators	*/
				 ":.-",	/* Key/salt separators	*/
				 0,	/* No duplicates	*/
				 &params.keysalts,
				 &params.num_keysalts);
	 if (params.num_keysalts)
	      params.mask |= KADM5_CONFIG_ENCTYPES;

	 krb5_xfree(svalue);
    }
    
	hierarchy[2] = "iprop_enable";

	params.iprop_enabled = FALSE;
	params.mask |= KADM5_CONFIG_IPROP_ENABLED;

	if (params_in->mask & KADM5_CONFIG_IPROP_ENABLED) {
		params.mask |= KADM5_CONFIG_IPROP_ENABLED;
		params.iprop_enabled = params_in->iprop_enabled;
	} else {
		krb5_boolean bvalue;
		if (aprofile &&
		    !krb5_aprof_get_boolean(aprofile, hierarchy, TRUE, &bvalue)) {
		    params.iprop_enabled = bvalue;
		    params.mask |= KADM5_CONFIG_IPROP_ENABLED;
		}
	}

	if (!GET_STRING_PARAM(iprop_logfile, KADM5_CONFIG_IPROP_LOGFILE,
			      "iprop_logfile", NULL)) {
	    if (params.mask & KADM5_CONFIG_DBNAME) {
		if (asprintf(&params.iprop_logfile, "%s.ulog", params.dbname) >= 0) {
		    params.mask |= KADM5_CONFIG_IPROP_LOGFILE;
		}
	    }
	}

	GET_PORT_PARAM(iprop_port, KADM5_CONFIG_IPROP_PORT,
		       "iprop_port", 0);

	hierarchy[2] = "iprop_master_ulogsize";

	params.iprop_ulogsize = DEF_ULOGENTRIES;
	params.mask |= KADM5_CONFIG_ULOG_SIZE;

	if (params_in->mask & KADM5_CONFIG_ULOG_SIZE) {
		params.mask |= KADM5_CONFIG_ULOG_SIZE;
		params.iprop_ulogsize = params_in->iprop_ulogsize;
	} else {
		if (aprofile && !krb5_aprof_get_int32(aprofile, hierarchy,
		    TRUE, &ivalue)) {
			if (ivalue > MAX_ULOGENTRIES)
				params.iprop_ulogsize = MAX_ULOGENTRIES;
			else if (ivalue <= 0)
				params.iprop_ulogsize = DEF_ULOGENTRIES;
			else
				params.iprop_ulogsize = ivalue;
			params.mask |= KADM5_CONFIG_ULOG_SIZE;
		}
	}

	GET_DELTAT_PARAM(iprop_poll_time, KADM5_CONFIG_POLL_TIME,
			 "iprop_slave_poll", 2 * 60); /* 2m */

    *params_out = params;
    
cleanup:
    if (aprofile)
	krb5_aprof_finish(aprofile);
    if (kret) {
	 kadm5_free_config_params(context, &params);
	 params_out->mask = 0;
    }
    return(kret);
}
/*
 * kadm5_free_config_params()	- Free data allocated by above.
 */
krb5_error_code
kadm5_free_config_params(context, params)
    krb5_context	context;
    kadm5_config_params	*params;
{
    if (params) {
	krb5_xfree(params->dbname);
	krb5_xfree(params->mkey_name);
	krb5_xfree(params->stash_file);
	krb5_xfree(params->keysalts);
	free(params->admin_server);
	free(params->admin_keytab);
	free(params->dict_file);
	free(params->acl_file);
	free(params->realm);
    }
    return(0);
}

krb5_error_code
kadm5_get_admin_service_name(krb5_context ctx,
			     char *realm_in,
			     char *admin_name,
			     size_t maxlen)
{
    krb5_error_code ret;
    kadm5_config_params params_in, params_out;
    struct hostent *hp;

    memset(&params_in, 0, sizeof(params_in));
    memset(&params_out, 0, sizeof(params_out));

    params_in.mask |= KADM5_CONFIG_REALM;
    params_in.realm = realm_in;
    ret = kadm5_get_config_params(ctx, 0, &params_in, &params_out);
    if (ret)
	return ret;

    if (!(params_out.mask & KADM5_CONFIG_ADMIN_SERVER)) {
	ret = KADM5_MISSING_KRB5_CONF_PARAMS;
	goto err_params;
    }

    hp = gethostbyname(params_out.admin_server);
    if (hp == NULL) {
	ret = errno;
	goto err_params;
    }
    if (strlen(hp->h_name) + sizeof("kadmin/") > maxlen) {
	ret = ENOMEM;
	goto err_params;
    }
    snprintf(admin_name, maxlen, "kadmin/%s", hp->h_name);

err_params:
    kadm5_free_config_params(ctx, &params_out);
    return ret;
}

/***********************************************************************
 * This is the old krb5_realm_read_params, which I mutated into
 * kadm5_get_config_params but which old KDC code still uses.
 ***********************************************************************/

/*
 * krb5_read_realm_params()	- Read per-realm parameters from KDC
 *				  alternate profile.
 */
krb5_error_code
krb5_read_realm_params(kcontext, realm, rparamp)
    krb5_context	kcontext;
    char		*realm;
    krb5_realm_params	**rparamp;
{
    char		*filename;
    char		*envname;
    char		*lrealm;
    krb5_pointer	aprofile = 0;
    krb5_realm_params	*rparams;
    const char		*hierarchy[4];
    char		*svalue;
    krb5_int32		ivalue;
    krb5_boolean	bvalue;
    krb5_deltat		dtvalue;

    char		*kdcprofile = 0;
    char		*kdcenv = 0;

    krb5_error_code	kret;

    filename = (kdcprofile) ? kdcprofile : DEFAULT_KDC_PROFILE;
    envname = (kdcenv) ? kdcenv : KDC_PROFILE_ENV;

    if (kcontext->profile_secure == TRUE) envname = 0;

    rparams = (krb5_realm_params *) NULL;
    if (realm)
	lrealm = strdup(realm);
    else {
	kret = krb5_get_default_realm(kcontext, &lrealm);
	if (kret)
	    goto cleanup;
    }

    kret = krb5_aprof_init(filename, envname, &aprofile);
    if (kret)
	goto cleanup;
    
    rparams = (krb5_realm_params *) malloc(sizeof(krb5_realm_params));
    if (rparams == 0) {
	kret = ENOMEM;
	goto cleanup;
    }

    /* Initialize realm parameters */
    memset((char *) rparams, 0, sizeof(krb5_realm_params));

    /* Get the value for the database */
    hierarchy[0] = "realms";
    hierarchy[1] = lrealm;
    hierarchy[2] = "database_name";
    hierarchy[3] = (char *) NULL;
    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue))
	rparams->realm_dbname = svalue;
	
    /* Get the value for the KDC port list */
    hierarchy[2] = "kdc_ports";
    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue))
	rparams->realm_kdc_ports = svalue;
    hierarchy[2] = "kdc_tcp_ports";
    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue))
	rparams->realm_kdc_tcp_ports = svalue;

    /* Get the name of the acl file */
    hierarchy[2] = "acl_file";
    if (!krb5_aprof_get_string(aprofile, hierarchy, TRUE, &svalue))
	rparams->realm_acl_file = svalue;
	    
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

    hierarchy[2] = "reject_bad_transit";
    if (!krb5_aprof_get_boolean(aprofile, hierarchy, TRUE, &bvalue)) {
	rparams->realm_reject_bad_transit = bvalue;
	rparams->realm_reject_bad_transit_valid = 1;
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
		while (isspace((int) *tp) && (tp < sp)) {
		    *tp = '\0';
		    tp--;
		}
		*ep = '\0';
		ep++;
		/* Skip over trailing whitespace of ep */
		while (isspace((int) *ep) && (*ep)) ep++;
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

    rparams->realm_keysalts = NULL;
    rparams->realm_num_keysalts = 0;

cleanup:
    if (aprofile)
	krb5_aprof_finish(aprofile);
    free(lrealm);
    if (kret) {
	if (rparams)
	    krb5_free_realm_params(kcontext, rparams);
	rparams = 0;
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
	krb5_xfree(rparams->realm_profile);
	krb5_xfree(rparams->realm_dbname);
	krb5_xfree(rparams->realm_mkey_name);
	krb5_xfree(rparams->realm_stash_file);
	krb5_xfree(rparams->realm_keysalts);
	krb5_xfree(rparams->realm_kdc_ports);
	krb5_xfree(rparams->realm_kdc_tcp_ports);
	krb5_xfree(rparams->realm_acl_file);
	krb5_xfree(rparams);
    }
    return(0);
}


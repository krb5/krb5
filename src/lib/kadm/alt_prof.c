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
 *
 * XXX is this really necessary?
 */
#include "krb5.h"
#include "profile.h"
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
    extern char		*getenv PROTOTYPE((char *));
    
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
 *	EINVAL			- Invalid syntax.
 *
 * Valid formats are:
 *	<days>-<hours>:<minutes>:<seconds>
 *	<days>d <hours>h <minutes>m <seconds>s
 *	<hours>:<minutes>:<seconds>
 *	<hours>h <minutes>m <seconds>s
 *	<hours>:<minutes>
 *	<hours>h <minutes>m
 *	<seconds>
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
    krb5_boolean	found;
    int			days, hours, minutes, seconds;
    krb5_deltat		dt;

    if (!(kret = krb5_aprof_getvals(acontext, hierarchy, &values))) {
	index = 0;
	if (uselast) {
	    for (index=0; values[index]; index++);
	    index--;
	}
	valp = values[index];
	days = hours = minutes = seconds = 0;
	found = 0;

	/*
	 * Blast our way through potential syntaxes until we find a match.
	 */
	if (sscanf(valp, "%d-%d:%d:%d", &days, &hours, &minutes, &seconds)
	    == 4)
	    found = 1;
	else if (sscanf(valp, "%dd %dh %dm %ds",
			&days, &hours, &minutes, &seconds) == 4)
	    found = 1;
	else if (sscanf(valp, "%d:%d:%d", &hours, &minutes, &seconds) == 3) {
	    found = 1;
	    days = 0;
	}
	else if (sscanf(valp, "%dh %dm %ds", &hours, &minutes, &seconds)
		 == 3) {
	    found = 1;
	    days = 0;
	}
	else if (sscanf(valp, "%d:%d", &hours, &minutes) == 2) {
	    found = 1;
	    days = seconds = 0;
	}
	else if (sscanf(valp, "%dh %dm", &hours, &minutes) == 2) {
	    found = 1;
	    days = seconds = 0;
	}
	else if (sscanf(valp, "%d", &seconds) == 1) {
	    found = 1;
	    days = hours = minutes = 0;
	}

	/* If found, calculate the delta value */
	if (found) {
	    dt = days;
	    dt *= 24;
	    dt += hours;
	    dt *= 60;
	    dt += minutes;
	    dt *= 60;
	    dt += seconds;
	    *deltatp = dt;
	}
	else
	    kret = EINVAL;

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

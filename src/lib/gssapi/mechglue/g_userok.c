/*
 * Copyright (C) 2011 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)g_userok.c	1.1	04/03/25 SMI" */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mglueP.h>
#include <gssapi/gssapi.h>

static const char localLoginUserAttr[] = "local-login-user";

static OM_uint32
mech_userok(OM_uint32 *minor,
	    const gss_union_name_t unionName,
	    const char *user,
	    int *user_ok)
{
	OM_uint32 major = GSS_S_UNAVAILABLE;
	gss_mechanism mech;

	/* may need to import the name if this is not MN */
	if (unionName->mech_type == GSS_C_NO_OID)
		return (GSS_S_FAILURE);

	mech = gssint_get_mechanism(unionName->mech_type);
	if (mech == NULL)
		return (GSS_S_UNAVAILABLE);

	if (mech->gss_userok) {
		major = mech->gss_userok(minor, unionName->mech_name, user, user_ok);
		if (major != GSS_S_COMPLETE)
			map_error(minor, mech);
	}

	return (major);
}

/*
 * Naming extensions based local login authorization.
 */
static OM_uint32
attr_userok(OM_uint32 *minor,
	    const gss_name_t name,
	    const char *user,
	    int *user_ok)
{
	OM_uint32 major = GSS_S_UNAVAILABLE;
	OM_uint32 tmpMinor;
	size_t userLen = strlen(user);
	int more = -1;
	gss_buffer_desc attribute;

	*user_ok = 0;

	attribute.length = sizeof(localLoginUserAttr) - 1;
	attribute.value = (void *)localLoginUserAttr;

	while (more != 0 && *user_ok == 0) {
		gss_buffer_desc value;
		gss_buffer_desc display_value;
		int authenticated = 0, complete = 0;

		major = gss_get_name_attribute(minor,
					       name,
					       &attribute,
					       &authenticated,
					       &complete,
					       &value,
					       &display_value,
					       &more);
		if (GSS_ERROR(major))
			break;

		if (authenticated && complete &&
		    value.length == userLen &&
		    memcmp(value.value, user, userLen) == 0)
			*user_ok = 1;

		gss_release_buffer(&tmpMinor, &value);
		gss_release_buffer(&tmpMinor, &display_value);
	}

	return (major);
}

/*
 * Equality based local login authorization.
 */
static OM_uint32
compare_names_userok(OM_uint32 *minor,
		     const gss_OID mech_type,
		     const gss_name_t name,
		     const char *user,
		     int *user_ok)
{

	OM_uint32 status, tmpMinor;
	gss_name_t imported_name;
	gss_name_t canon_name;
	gss_buffer_desc gss_user;
	int match = 0;

	*user_ok = 0;

	gss_user.value = (void *)user;
	if (gss_user.value == NULL ||
	    name == GSS_C_NO_NAME ||
	    mech_type == GSS_C_NO_OID)
		return (GSS_S_BAD_NAME);
	gss_user.length = strlen(gss_user.value);

	status = gss_import_name(minor,
				&gss_user,
				GSS_C_NT_USER_NAME,
				&imported_name);
	if (status != GSS_S_COMPLETE) {
		goto out;
	}

	status = gss_canonicalize_name(minor,
				    imported_name,
				    mech_type,
				    &canon_name);
	if (status != GSS_S_COMPLETE) {
		(void) gss_release_name(&tmpMinor, &imported_name);
		goto out;
	}

	status = gss_compare_name(minor,
				canon_name,
				name,
				&match);
	(void) gss_release_name(&tmpMinor, &canon_name);
	(void) gss_release_name(&tmpMinor, &imported_name);
	if (status == GSS_S_COMPLETE) {
		if (match)
			*user_ok = 1; /* remote user is a-ok */
	}

out:
	return (status);
}


OM_uint32
gss_userok(OM_uint32 *minor,
	   const gss_name_t name,
	   const char *user,
	   int *user_ok)

{
	OM_uint32 major;
	gss_union_name_t unionName;

	if (minor == NULL || user_ok == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (name == NULL || user == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	*user_ok = 0;
	*minor = 0;

	unionName = (gss_union_name_t)name;

	/* If mech returns yes, we return yes */
	major = mech_userok(minor, unionName, user, user_ok);
	if (major == GSS_S_COMPLETE && *user_ok)
		return (GSS_S_COMPLETE);

	/* If attribute exists, we evaluate attribute */
	if (attr_userok(minor, name, user, user_ok) == GSS_S_COMPLETE)
		return (GSS_S_COMPLETE);

	/* If mech returns unavail, we compare the local name */
	if (major == GSS_S_UNAVAILABLE) {
		major = compare_names_userok(minor, unionName->mech_type,
					     name, user, user_ok);
	}

	return (major);
} /* gss_userok */

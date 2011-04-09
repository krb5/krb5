/*
 * Copyright (c) 2011, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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

static OM_uint32
mech_authorize_localname(OM_uint32 *minor,
			 const gss_union_name_t unionName,
			 const gss_union_name_t unionUser,
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

	if (mech->gssspi_authorize_localname) {
		major = mech->gssspi_authorize_localname(minor,
							 unionName->mech_name,
							 unionUser->external_name,
							 unionUser->name_type,
							 user_ok);
		if (major != GSS_S_COMPLETE)
			map_error(minor, mech);
	}

	return (major);
}

/*
 * Naming extensions based local login authorization.
 */
static OM_uint32
attr_authorize_localname(OM_uint32 *minor,
			 const gss_name_t name,
			 const gss_union_name_t unionUser,
			 int *user_ok)
{
	OM_uint32 major = GSS_S_UNAVAILABLE;
	OM_uint32 tmpMinor;
	gss_buffer_t externalName;
	int more = -1;

	*user_ok = 0;

	if (unionUser->name_type != GSS_C_NO_OID &&
	    !g_OID_equal(unionUser->name_type, GSS_C_NT_USER_NAME))
		return (GSS_S_BAD_NAMETYPE);

	externalName = unionUser->external_name;
	assert(externalName != GSS_C_NO_BUFFER);

	while (more != 0 && *user_ok == 0) {
		gss_buffer_desc value;
		gss_buffer_desc display_value;
		int authenticated = 0, complete = 0;

		major = gss_get_name_attribute(minor,
					       name,
					       GSS_C_ATTR_LOCAL_LOGIN_USER,
					       &authenticated,
					       &complete,
					       &value,
					       &display_value,
					       &more);
		if (GSS_ERROR(major))
			break;

		if (authenticated &&
		    value.length == externalName->length &&
		    memcmp(value.value, externalName->value, externalName->length) == 0)
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
compare_names_authorize_localname(OM_uint32 *minor,
				 const gss_union_name_t unionName,
				 const gss_name_t user,
				 int *user_ok)
{

	OM_uint32 status, tmpMinor;
	gss_name_t canonName;
	int match = 0;

	*user_ok = 0;

	status = gss_canonicalize_name(minor,
				       user,
				       unionName->mech_type,
				       &canonName);
	if (status != GSS_S_COMPLETE)
		return (status);

	status = gss_compare_name(minor,
				  (gss_name_t)unionName,
				  canonName,
				  &match);
	if (status == GSS_S_COMPLETE && match)
		*user_ok = 1; /* remote user is a-ok */

	(void) gss_release_name(&tmpMinor, &canonName);

	return (status);
}

OM_uint32
gss_authorize_localname(OM_uint32 *minor,
			const gss_name_t name,
			const gss_name_t user,
			int *user_ok)

{
	OM_uint32 major;
	gss_union_name_t unionName;
	gss_union_name_t unionUser;

	if (minor == NULL || user_ok == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	if (name == GSS_C_NO_NAME || user == GSS_C_NO_NAME)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	*user_ok = 0;
	*minor = 0;

	unionName = (gss_union_name_t)name;
	unionUser = (gss_union_name_t)user;

	if (unionUser->mech_type != GSS_C_NO_OID)
		return (GSS_S_BAD_NAME);

	/* If mech returns yes, we return yes */
	major = mech_authorize_localname(minor, unionName,
					 unionUser, user_ok);
	if (major == GSS_S_COMPLETE && *user_ok)
		return (GSS_S_COMPLETE);

	/* If attribute exists, we evaluate attribute */
	if (attr_authorize_localname(minor, unionName,
				     unionUser, user_ok) == GSS_S_COMPLETE)
		return (GSS_S_COMPLETE);

	/* If mech returns unavail, we compare the local name */
	if (major == GSS_S_UNAVAILABLE &&
	    unionName->mech_type != GSS_C_NO_OID) {
		major = compare_names_authorize_localname(minor,
							  unionName,
							  unionUser,
							  user_ok);
	}

	return (major);
}

int
gss_userok(const gss_name_t name,
	   const char *user)
{
	OM_uint32 major, minor;
	gss_buffer_desc userBuf;
	gss_name_t userName;
	int user_ok = 0;

	userBuf.value = (void *)user;
	userBuf.length = strlen(user);

	major = gss_import_name(&minor, &userBuf, GSS_C_NO_OID, &userName);
	if (GSS_ERROR(major))
		return (0);

	major = gss_authorize_localname(&minor, name, userName, &user_ok);
	if (GSS_ERROR(major))
		user_ok = 0;

	(void) gss_release_name(&minor, &userName);

	return (user_ok);
}

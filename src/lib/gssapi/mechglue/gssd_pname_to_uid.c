/* #pragma ident	"@(#)gssd_pname_to_uid.c	1.18	04/02/23 SMI" */
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
 * Copyright 1996 by Sun Microsystems, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of Sun Microsystems not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. Sun Microsystems makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * SUN MICROSYSTEMS DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL SUN MICROSYSTEMS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 *  glue routines that test the mech id either passed in to
 *  gss_init_sec_contex() or gss_accept_sec_context() or within the glue
 *  routine supported version of the security context and then call
 *  the appropriate underlying mechanism library procedure.
 *
 */

#include "mglueP.h"

#ifndef NO_PASSWORD
#include <pwd.h>
#endif

static OM_uint32
attr_pname_to_uid(OM_uint32 *minor,
                  const gss_mechanism mech,
                  const gss_name_t mech_name,
                  uid_t *uidp)
{
    OM_uint32 major = GSS_S_UNAVAILABLE;
#ifndef NO_PASSWORD
    OM_uint32 tmpMinor;
    int more = -1;

    if (mech->gss_get_name_attribute == NULL)
        return GSS_S_UNAVAILABLE;

    while (more != 0) {
        gss_buffer_desc value;
        gss_buffer_desc display_value;
        int authenticated = 0, complete = 0, code;
        char pwbuf[BUFSIZ];
        struct passwd pw, *pwd;
        char *localLoginUser;

        major = mech->gss_get_name_attribute(minor,
                                             mech_name,
                                             GSS_C_ATTR_LOCAL_LOGIN_USER,
                                             &authenticated,
                                             &complete,
                                             &value,
                                             &display_value,
                                             &more);
        if (GSS_ERROR(major)) {
            map_error(minor, mech);
            break;
        }

        localLoginUser = malloc(value.length + 1);
        if (localLoginUser == NULL) {
            major = GSS_S_FAILURE;
            *minor = ENOMEM;
            break;
        }

        memcpy(localLoginUser, value.value, value.length);
        localLoginUser[value.length] = '\0';

        code = k5_getpwnam_r(localLoginUser, &pw, pwbuf, sizeof(pwbuf), &pwd);

        free(localLoginUser);
        gss_release_buffer(&tmpMinor, &value);
        gss_release_buffer(&tmpMinor, &display_value);

        if (code == 0 && pwd != NULL) {
            *uidp = pwd->pw_uid;
            major = GSS_S_COMPLETE;
            *minor = 0;
            break;
        } else
            major = GSS_S_UNAVAILABLE;
    }
#endif /* !NO_PASSWORD */

    return major;
}

OM_uint32 KRB5_CALLCONV
gss_pname_to_uid(OM_uint32 *minor,
                 const gss_name_t pname,
                 const gss_OID mech_type,
                 uid_t *uidp)
{
    OM_uint32 major, tmpMinor;
    gss_mechanism mech;
    gss_union_name_t unionName;
    gss_name_t mechName = GSS_C_NO_NAME, mechNameP;

    /*
     * find the appropriate mechanism specific pname_to_uid procedure and
     * call it.
     */
    if (minor == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor = 0;

    if (pname == GSS_C_NO_NAME)
        return GSS_S_CALL_INACCESSIBLE_READ;

    if (uidp == NULL)
        return GSS_S_CALL_INACCESSIBLE_WRITE;

    unionName = (gss_union_name_t)pname;

    if (mech_type != GSS_C_NO_OID)
        mech = gssint_get_mechanism(mech_type);
    else
        mech = gssint_get_mechanism(unionName->mech_type);

    if (mech == NULL)
	return GSS_S_UNAVAILABLE;

    /* may need to create a mechanism specific name */
    if (unionName->mech_type == GSS_C_NO_OID ||
        (unionName->mech_type != GSS_C_NO_OID &&
         !g_OID_equal(unionName->mech_type, &mech->mech_type))) {
        major = gssint_import_internal_name(minor, &mech->mech_type,
                                            unionName, &mechName);
        if (GSS_ERROR(major))
            return major;

        mechNameP = mechName;
    } else
        mechNameP = unionName->mech_name;

    major = GSS_S_UNAVAILABLE;

    if (mech->gss_pname_to_uid != NULL) {
        major = mech->gss_pname_to_uid(minor, mechNameP, mech_type, uidp);
        if (GSS_ERROR(major))
            map_error(minor, mech);
    }

    if (GSS_ERROR(major))
        major = attr_pname_to_uid(minor, mech, mechNameP, uidp);

    if (mechName != GSS_C_NO_NAME)
        gssint_release_internal_name(&tmpMinor, &mech->mech_type, &mechName);

    return major;
}

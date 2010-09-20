/* #pragma ident	"@(#)g_imp_name.c	1.26	04/02/23 SMI" */

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
 *  glue routine gss_import_name
 *
 */

#include "mglueP.h"
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>

/* local function to import GSS_C_EXPORT_NAME names */
static OM_uint32
importExportName(OM_uint32 *minor_status,
		 gss_union_name_t union_name,
		 gss_OID *mech_type,
		 gss_name_t *mech_name,
		 gss_name_attribute_t *attrs);

static OM_uint32
val_imp_name_args(
    OM_uint32 *minor_status,
    gss_buffer_t input_name_buffer,
    gss_OID input_name_type,
    gss_name_t *output_name)
{

    /* Initialize outputs. */

    if (minor_status != NULL)
	*minor_status = 0;

    if (output_name != NULL)
	*output_name = GSS_C_NO_NAME;

    /* Validate arguments. */

    if (minor_status == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if (output_name == NULL)
	return (GSS_S_CALL_INACCESSIBLE_WRITE);

    if (input_name_buffer == GSS_C_NO_BUFFER)
	return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME);

    if (input_name_buffer->length == 0)
	return GSS_S_BAD_NAME;

    if (input_name_buffer->value == NULL)
	return (GSS_S_CALL_INACCESSIBLE_READ | GSS_S_BAD_NAME);

    return (GSS_S_COMPLETE);
}


OM_uint32 KRB5_CALLCONV
gss_import_name(minor_status,
                input_name_buffer,
                input_name_type,
                output_name)

OM_uint32 *		minor_status;
gss_buffer_t		input_name_buffer;
gss_OID			input_name_type;
gss_name_t *		output_name;

{
    gss_union_name_t	union_name;
    OM_uint32		tmp, major_status = GSS_S_FAILURE;

    major_status = val_imp_name_args(minor_status,
				     input_name_buffer, input_name_type,
				     output_name);
    if (major_status != GSS_S_COMPLETE)
	return (major_status);

    /*
     * First create the union name struct that will hold the external
     * name and the name type.
     */
    union_name = (gss_union_name_t) malloc (sizeof(gss_union_name_desc));
    if (!union_name)
	return (GSS_S_FAILURE);

    union_name->loopback = 0;
    union_name->mech_type = 0;
    union_name->mech_name = 0;
    union_name->name_type = 0;
    union_name->external_name = 0;
    union_name->attributes = NULL;

    /*
     * All we do here is record the external name and name_type.
     * When the name is actually used, the underlying gss_import_name()
     * is called for the appropriate mechanism.  The exception to this
     * rule is when the name of GSS_C_NT_EXPORT_NAME type.  If that is
     * the case, then we make it MN in this call.
     */
    major_status = gssint_create_copy_buffer(input_name_buffer,
					    &union_name->external_name, 0);
    if (major_status != GSS_S_COMPLETE) {
	free(union_name);
	return (major_status);
    }

    if (input_name_type != GSS_C_NULL_OID) {
	major_status = generic_gss_copy_oid(minor_status,
					    input_name_type,
					    &union_name->name_type);
	if (major_status != GSS_S_COMPLETE) {
	    map_errcode(minor_status);
	    goto allocation_failure;
	}
    }

    /*
     * In MIT Distribution the mechanism is determined from the nametype;
     * This is not a good idea - first mechanism that supports a given
     * name type is picked up; later on the caller can request a
     * different mechanism. So we don't determine the mechanism here. Now
     * the user level and kernel level import_name routine looks similar
     * except the kernel routine makes a copy of the nametype structure. We
     * do however make this an MN for names of GSS_C_NT_EXPORT_NAME type.
     */
    if (input_name_type != GSS_C_NULL_OID &&
	(g_OID_equal(input_name_type, GSS_C_NT_EXPORT_NAME) ||
	 g_OID_equal(input_name_type, GSS_C_NT_COMPOSITE_EXPORT))) {
	major_status = importExportName(minor_status,
					union_name,
					&union_name->mech_type,
					&union_name->mech_name,
					&union_name->attributes);
	if (major_status != GSS_S_COMPLETE)
	    goto allocation_failure;
    }

    union_name->loopback = union_name;
    *output_name = (gss_name_t)union_name;
    return (GSS_S_COMPLETE);

allocation_failure:
    if (union_name) {
	if (union_name->external_name) {
	    if (union_name->external_name->value)
		free(union_name->external_name->value);
	    free(union_name->external_name);
	}
	if (union_name->name_type)
	    generic_gss_release_oid(&tmp, &union_name->name_type);
	if (union_name->mech_name)
	    gssint_release_internal_name(minor_status, union_name->mech_type,
					&union_name->mech_name);
	if (union_name->mech_type)
	    generic_gss_release_oid(&tmp, &union_name->mech_type);
	free(union_name);
    }
    return (major_status);
}

static OM_uint32
importCompositeName(OM_uint32 *minor_status,
                    gss_buffer_t name_buf,
                    gss_name_attribute_t *pAttributes)
{
    OM_uint32 status, tmpMinor;
    gss_name_attribute_t head = NULL, *pNext = &head;
    size_t remain = name_buf->length;
    unsigned char *p = (unsigned char *)name_buf->value;
    ssize_t attrCount;

    *pAttributes = NULL;

    if (remain < 4)
        return GSS_S_BAD_NAME;

    TREAD_INT(p, attrCount, 1);
    remain -= 4;

    do {
        gss_name_attribute_t attr;

        status = gssint_name_attribute_internalize(minor_status, &attr, &pNext,
                                                   &p, &remain);
        if (GSS_ERROR(status))
            break;

        attrCount--;
    } while (remain != 0);

    if (attrCount != 0)
        status = GSS_S_BAD_NAME;

    if (GSS_ERROR(status))
        gssint_release_name_attributes(&tmpMinor, &head);
    else
        *pAttributes = head;

    return status;
}

/*
 * GSS export name constants
 */
static const unsigned int expNameTokIdLen = 2;
static const unsigned int mechOidLenLen = 2;
static const unsigned int nameTypeLenLen = 2;

static OM_uint32
importExportName(OM_uint32 *minor,
		 gss_union_name_t unionName,
		 gss_OID *mech_type,
		 gss_name_t *mech_name,
		 gss_name_attribute_t *attributes)
{
    gss_OID_desc mechOid;
    gss_buffer_desc expName;
    unsigned char *buf;
    gss_mechanism mech;
    OM_uint32 major, tmpMinor;
    OM_uint32 mechOidLen, nameLen, curLength;
    unsigned int bytes;
    int composite;

    expName.value = unionName->external_name->value;
    expName.length = unionName->external_name->length;

    curLength = expNameTokIdLen + mechOidLenLen;
    if (expName.length < curLength)
	return (GSS_S_DEFECTIVE_TOKEN);

    buf = (unsigned char *)expName.value;
    if (buf[0] != 0x04)
	return (GSS_S_DEFECTIVE_TOKEN);
    if (buf[1] != 0x01 && buf[1] != 0x02)
	return (GSS_S_DEFECTIVE_TOKEN);

    composite = (buf[1] == 0x02);
    /*
     * MIT 1.8 emits composite tokens with GSS_C_NT_EXPORT, because
     * GSS_C_NT_COMPOSITE_EXPORT was not defined then. So accept
     * this, but if the new OID is specified, require composite
     * tokens.
     */
    if (g_OID_equal(unionName->name_type, GSS_C_NT_COMPOSITE_EXPORT) &&
	composite == 0)
	return (GSS_S_DEFECTIVE_TOKEN);

    buf += expNameTokIdLen;

    /* extract the mechanism oid length */
    mechOidLen = (*buf++ << 8);
    mechOidLen |= (*buf++);
    curLength += mechOidLen;
    if (expName.length < curLength)
	return (GSS_S_DEFECTIVE_TOKEN);
    /*
     * The mechOid itself is encoded in DER format, OID Tag (0x06)
     * length and the value of mech_OID
     */
    if (*buf++ != 0x06)
	return (GSS_S_DEFECTIVE_TOKEN);

    /*
     * mechoid Length is encoded twice; once in 2 bytes as
     * explained in RFC2743 (under mechanism independent exported
     * name object format) and once using DER encoding
     *
     * We verify both lengths.
     */

    mechOid.length = gssint_get_der_length(&buf,
				    (expName.length - curLength), &bytes);
    mechOid.elements = (void *)buf;

    /*
     * 'bytes' is the length of the DER length, '1' is for the DER
     * tag for OID
     */
    if ((bytes + mechOid.length + 1) != mechOidLen)
	return (GSS_S_DEFECTIVE_TOKEN);

    buf += mechOid.length;
    if ((mech = gssint_get_mechanism(&mechOid)) == NULL)
	return (GSS_S_BAD_MECH);

    if (mech->gss_import_name == NULL)
	return (GSS_S_UNAVAILABLE);

    /*
     * we must now determine if we should unwrap the name ourselves
     * or make the mechanism do it - we should only unwrap it
     * if we create it; so if mech->gss_export_name == NULL, we must
     * have created it.
     */
    if (composite ? mech->gss_export_name_composite : mech->gss_export_name) {
	major = mech->gss_import_name(minor,
				      &expName,
				      composite
					? (gss_OID)GSS_C_NT_COMPOSITE_EXPORT
					: (gss_OID)GSS_C_NT_EXPORT_NAME,
				      mech_name);
	if (major != GSS_S_COMPLETE)
	    map_error(minor, mech);
	else {
	    major = generic_gss_copy_oid(minor, &mechOid,
					 mech_type);
	    if (major != GSS_S_COMPLETE) {
		gssint_release_internal_name(&tmpMinor, &mechOid, mech_name);
		map_errcode(minor);
	    }
	}
	return (major);
    }
    /*
     * we must have exported the name - so we now need to reconstruct it
     * and call the mechanism to create it
     *
     * WARNING:	Older versions of gssint_export_internal_name() did
     *		not export names correctly, but now it does.  In
     *		order to stay compatible with existing exported
     *		names we must support names exported the broken
     *		way.
     *
     * Specifically, gssint_export_internal_name() used to include
     * the name type OID in the encoding of the exported MN.
     * Additionally, the Kerberos V mech used to make display names
     * that included a null terminator which was counted in the
     * display name gss_buffer_desc.
     */
    curLength += 4;		/* 4 bytes for name len */
    if (expName.length < curLength)
	return (GSS_S_DEFECTIVE_TOKEN);

    /* next 4 bytes in the name are the name length */
    nameLen = load_32_be(buf);
    buf += 4;

    /*
     * we use < here because bad code in rpcsec_gss rounds up exported
     * name token lengths and pads with nulls, otherwise != would be
     * appropriate, for the non-composite name case (the composite
     * name is appended to the end of the simple name, so an equality
     * check would be inappropriate)
     */
    curLength += nameLen;   /* this is the total length */
    if (expName.length < curLength)
	return (GSS_S_DEFECTIVE_TOKEN);

    /*
     * We detect broken exported names here: they always start with
     * a two-octet network-byte order OID length, which is always
     * less than 256 bytes, so the first octet of the length is
     * always '\0', which is not allowed in GSS-API display names
     * (or never occurs in them anyways).  Of course, the OID
     * shouldn't be there, but it is.  After the OID (sans DER tag
     * and length) there's the name itself, though null-terminated;
     * this null terminator should also not be there, but it is.
     */
    if (!composite && nameLen > 0 && *buf == '\0') {
	OM_uint32 nameTypeLen;
	/* next two bytes are the name oid */
	if (nameLen < nameTypeLenLen)
	    return (GSS_S_DEFECTIVE_TOKEN);

	nameLen -= nameTypeLenLen;

	nameTypeLen = (*buf++) << 8;
	nameTypeLen |= (*buf++);

	if (nameLen < nameTypeLen)
	    return (GSS_S_DEFECTIVE_TOKEN);

	buf += nameTypeLen;
	nameLen -= nameTypeLen;

	/*
	 * adjust for expected null terminator that should
	 * really not be there
	 */
	if (nameLen > 0 && *(buf + nameLen - 1) == '\0')
	    nameLen--;
    }

    /*
     * Can a name be null?  Let the mech decide.
     *
     * NOTE: We use GSS_C_NULL_OID as the name type when importing
     *	 the unwrapped name.  Presumably the exported name had,
     *	 prior to being exported been obtained in such a way
     *	 that it has been properly perpared ("canonicalized," in
     *	 GSS-API terms) accroding to some name type; we cannot
     *	 tell what that name type was now, but the name should
     *	 need no further preparation other than the lowest
     *	 common denominator afforded by the mech to names
     *	 imported with GSS_C_NULL_OID.  For the Kerberos V mech
     *	 this means doing less busywork too (particularly once
     *	 IDN is thrown in with Kerberos V extensions).
     */
    expName.length = nameLen;
    expName.value = nameLen ? (void *)buf : NULL;
    major = mech->gss_import_name(minor, &expName,
				  GSS_C_NULL_OID, mech_name);
    if (major != GSS_S_COMPLETE) {
	map_error(minor, mech);
	return (major);
    }

    major = generic_gss_copy_oid(minor, &mechOid, mech_type);
    if (major != GSS_S_COMPLETE) {
	map_errcode(minor);
	gssint_release_internal_name(&tmpMinor, &mechOid, mech_name);
	return (major);
    }

    if (composite && attributes != NULL) {
	expName.length = unionName->external_name->length - curLength;
	expName.value = buf + nameLen;

	major = importCompositeName(minor, &expName, attributes);
	if (major != GSS_S_COMPLETE) {
	    gssint_release_internal_name(&tmpMinor, &mechOid, mech_name);
	    return (major);
	}
    }

    return major;
} /* importExportName */

OM_uint32
gssint_import_internal_name(OM_uint32 *minor_status,
			    gss_OID mech_type,
			    gss_union_name_t union_name,
			    gss_name_t *internal_name)
{
    OM_uint32           status, tmpMinor;
    gss_mechanism       mech;

    /*
     * This path allows us to take advantage of internal import-
     * export name semantics (for use with self-exported composite
     * names). Otherwise, a mechanism that supports naming extensions
     * but not gss_export_name_composite will fail parsing a
     * composite name.
     */
    if (union_name->name_type != GSS_C_NULL_OID &&
	(g_OID_equal(union_name->name_type, GSS_C_NT_EXPORT_NAME) ||
	 g_OID_equal(union_name->name_type, GSS_C_NT_COMPOSITE_EXPORT))) {
	gss_OID actualMech = GSS_C_NO_OID;
	status = importExportName(minor_status,
				  union_name,
				  &actualMech,
				  internal_name,
				  NULL);
	if (status == GSS_S_COMPLETE &&
	    !g_OID_equal(mech_type, actualMech)) {
	    gssint_release_internal_name(&tmpMinor, mech_type, internal_name);
	    status = GSS_S_BAD_MECH;
	}

	return (status);
    }

    mech = gssint_get_mechanism (mech_type);
    if (mech == NULL)
        return (GSS_S_BAD_MECH);

    if (mech->gss_import_name == NULL)
        return (GSS_S_UNAVAILABLE);

    status = mech->gss_import_name(minor_status,
                                   union_name->external_name,
                                   union_name->name_type,
                                   internal_name);
    if (status != GSS_S_COMPLETE)
        map_error(minor_status, mech);

    return (status);
}

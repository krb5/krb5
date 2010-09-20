/* -*- mode: c; indent-tabs-mode: nil -*- */
/*
 * Copyright 2010 by the Massachusetts Institute of Technology.
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

#include "mglueP.h"

static OM_uint32
duplicateNameAttribute(OM_uint32 *minor_status,
                       gss_name_attribute_t src,
                       gss_name_attribute_t *pDst)
{
    OM_uint32 tmpMinor;
    gss_name_attribute_t dst;
    size_t i;

    dst = calloc(1, sizeof(gss_name_attribute_desc));
    if (dst == NULL)
        goto alloc_fail;

    if (!g_duplicate_buffer(&src->attribute, &dst->attribute))
        goto alloc_fail;

    dst->authenticated = src->authenticated;
    dst->complete = src->complete;

    if (src->values.count > 0) {
        dst->values.elements = calloc(src->values.count,
                                      sizeof(gss_buffer_desc));
        if (dst->values.elements == NULL)
            goto alloc_fail;

        dst->display_values.elements = calloc(src->values.count,
                                              sizeof(gss_buffer_desc));
        if (dst->display_values.elements == NULL)
            goto alloc_fail;

        for (i = 0; i < src->values.count; i++) {
            if (!g_duplicate_buffer(&src->values.elements[i],
                                    &dst->values.elements[i]))
                goto alloc_fail;
            if (!g_duplicate_buffer(&src->display_values.elements[i],
                                    &dst->display_values.elements[i]))
                goto alloc_fail;
        }
    }

    *pDst = dst;
    return GSS_S_COMPLETE;

alloc_fail:
    gssint_release_name_attribute(&tmpMinor, &dst);
    *minor_status = ENOMEM;
    return GSS_S_FAILURE;
}

OM_uint32
gssint_duplicate_name_attributes(OM_uint32 *minor_status,
                                 gss_name_attribute_t srcAttrs,
                                 gss_name_attribute_t *pDstAttrs)
{
    gss_name_attribute_t srcAttr;
    gss_name_attribute_t dstAttrHead = NULL, *pDstAttr = &dstAttrHead;
    OM_uint32 status, tmpMinor;

    for (srcAttr = srcAttrs; srcAttr != NULL; srcAttr = srcAttr->next) {
        gss_name_attribute_t dstAttr;

        status = duplicateNameAttribute(minor_status, srcAttr, &dstAttr);
        if (GSS_ERROR(status))
            goto cleanup;

        *pDstAttr = dstAttr;
        pDstAttr = &dstAttr->next;
    }

    *pDstAttrs = dstAttrHead;
    status = GSS_S_COMPLETE;

cleanup:
    if (GSS_ERROR(status))
        gssint_release_name_attributes(&tmpMinor, &dstAttrHead);

    return status;
}

OM_uint32
gssint_release_name_attribute(OM_uint32 *minor_status,
                              gss_name_attribute_t *pAttr)
{
    OM_uint32 tmpMinor;
    size_t i;
    gss_name_attribute_t attr = *pAttr;

    if (attr != NULL) {
        gss_release_buffer(&tmpMinor, &attr->attribute);

        for (i = 0; i < attr->values.count; i++) {
            gss_release_buffer(&tmpMinor, &attr->values.elements[i]);
            gss_release_buffer(&tmpMinor, &attr->display_values.elements[i]);
        }
        free(attr);
        *pAttr = NULL;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssint_get_name_attribute(OM_uint32 *minor_status,
                          gss_name_attribute_t attributes,
                          gss_buffer_t attr_name,
                          int *authenticated,
                          int *complete,
                          gss_buffer_t value,
                          gss_buffer_t display_value,
                          int *more)
{
    gss_name_attribute_t attr, found = NULL;
    int i = *more;
    OM_uint32 tmpMinor;

    *more = 0;

    for (attr = attributes; attr != NULL; attr = attr->next) {
        if (attr->attribute.length == attr_name->length &&
            !memcmp(attr->attribute.value, attr_name->value, attr_name->length)) {
            found = attr;
            break;
        }
    }

    if (found == NULL)
        return GSS_S_UNAVAILABLE;

    if (i == -1)
        i = 0;
    else if ((size_t)i >= attr->values.count)
        return GSS_S_UNAVAILABLE;

    if (attr->values.count > 0) {
        if (value != NULL &&
            !g_duplicate_buffer(&attr->values.elements[i], value)) {
            *minor_status = ENOMEM;
            return GSS_S_FAILURE;
        }
        if (display_value != NULL &&
            !g_duplicate_buffer(&attr->display_values.elements[i],
                                display_value)) {
            gss_release_buffer(&tmpMinor, value);
            return GSS_S_FAILURE;
        }
    }

    if (authenticated != NULL)
        *authenticated = attr->authenticated;
    if (complete != NULL)
        *complete = attr->complete;
    if (attr->values.count > (size_t)++i)
        *more = i;

    return GSS_S_COMPLETE;
}

/*
 * An encoded attribute looks like
 *
 *      uint32      attribute name length
 *      char[]      attribute name data
 *      uint32      attribute flags
 *      uint32      value count
 *      value[]     values
 *
 * where a value is:
 *
 *      uint32      value length
 *      char[]      value data
 *      uint32      display value length
 *      char[]      display value data
 *
 * The encoding of a set of attributes consists of the attribute
 * count following by the encoding of each attribute.
 *
 * All integers are big-endian.
 */
static size_t
nameAttributeSize(gss_name_attribute_t attr)
{
    size_t size, i;

    size = 4 + attr->attribute.length;
    size += 4; /* flags */
    size += 4; /* number of values */

    for (i = 0; i < attr->values.count; i++) {
        gss_buffer_t value = &attr->values.elements[i];
        gss_buffer_t display_value = &attr->display_values.elements[i];

        size += 4 + value->length;
        size += 4 + display_value->length;
    }

    return size;
}

static OM_uint32
nameAttributeExternalize(OM_uint32 *minor_status,
                         gss_name_attribute_t attr,
                         unsigned char **pBuffer,
                         size_t *pRemain)
{
    OM_uint32 flags = 0;
    unsigned char *p = *pBuffer;
    size_t i, remain = *pRemain;

    assert(remain >= nameAttributeSize(attr));

    if (attr->authenticated)
        flags |= NAME_FLAG_AUTHENTICATED;
    if (attr->complete)
        flags |= NAME_FLAG_COMPLETE;

    TWRITE_BUF(p, attr->attribute, 1);
    remain -= 4 + attr->attribute.length;

    TWRITE_INT(p, flags, 1);
    TWRITE_INT(p, attr->values.count, 1);
    remain -= 8;

    for (i = 0; i < attr->values.count; i++) {
        gss_buffer_t value = &attr->values.elements[i];
        gss_buffer_t display_value = &attr->display_values.elements[i];

        TWRITE_BUF(p, *value, 1);
        remain -= 4 + value->length;
        TWRITE_BUF(p, *display_value, 1);
        remain -= 4 + display_value->length;
    }

    *pBuffer = p;
    *pRemain = remain;

    return GSS_S_COMPLETE;
}

static OM_uint32
internalizeBuffer(OM_uint32 *minor_status,
                  gss_buffer_desc *buffer,
                  unsigned char **pBuffer,
                  size_t *pRemain)
{
    unsigned char *p = *pBuffer;
    size_t remain = *pRemain;

    if (remain < 4)
        return GSS_S_BAD_NAME;

    TREAD_INT(p, buffer->length, 1);
    remain -= 4;

    if (remain < buffer->length)
        return GSS_S_BAD_NAME;

    /* Attribute name */
    buffer->value = malloc(buffer->length + 1);
    if (buffer->value == NULL) {
        *minor_status = ENOMEM;
        return GSS_S_FAILURE;
    }

    memcpy(buffer->value, p, buffer->length);
    ((char *)buffer->value)[buffer->length] = '\0';

    *pBuffer = p + buffer->length;
    *pRemain = remain - buffer->length;

    return GSS_S_COMPLETE;
}

#define CHECK_REMAIN(len)   do {    \
    if ((remain) < len) {           \
        status = GSS_S_BAD_NAME;    \
        goto cleanup;               \
    }                               \
  } while (0)

OM_uint32
gssint_name_attribute_internalize(OM_uint32 *minor_status,
                                  gss_name_attribute_t *pAttr,
                                  gss_name_attribute_t **pNext,
                                  unsigned char **pBuffer,
                                  size_t *pRemain)
{
    OM_uint32 status, tmpMinor;
    unsigned char *p = *pBuffer;
    size_t i, remain = *pRemain;
    gss_name_attribute_t attr;
    OM_uint32 flags;

    attr = calloc(1, sizeof(*attr));
    if (attr == NULL) {
        *minor_status = ENOMEM;
        status = GSS_S_FAILURE;
        goto cleanup;
    }

    status = internalizeBuffer(minor_status, &attr->attribute, &p, &remain);
    if (GSS_ERROR(status))
        goto cleanup;

    CHECK_REMAIN(4);
    TREAD_INT(p, flags, 1);
    remain -= 4;

    if (flags & NAME_FLAG_AUTHENTICATED)
        attr->authenticated = 1;
    if (flags & NAME_FLAG_COMPLETE)
        attr->complete = 1;

    CHECK_REMAIN(4);
    TREAD_INT(p, attr->values.count, 1);
    remain -= 4;

    attr->display_values.count = attr->values.count;

    attr->values.elements = calloc(attr->values.count, sizeof(gss_buffer_desc));
    if (attr->values.elements == NULL) {
        *minor_status = ENOMEM;
        status = GSS_S_FAILURE;
        goto cleanup;
    }
    attr->display_values.elements = calloc(attr->display_values.count,
                                           sizeof(gss_buffer_desc));
    if (attr->display_values.elements == NULL) {
        *minor_status = ENOMEM;
        status = GSS_S_FAILURE;
        goto cleanup;
    }

    for (i = 0; i < attr->values.count; i++) {
        status = internalizeBuffer(minor_status, &attr->values.elements[i],
                                   &p, &remain);
        if (GSS_ERROR(status))
            goto cleanup;

        status = internalizeBuffer(minor_status,
                                   &attr->display_values.elements[i],
                                   &p, &remain);
        if (GSS_ERROR(status))
            goto cleanup;
    }

    *pAttr = attr;

    if (pNext != NULL) {
        assert(*pNext != NULL);

        **pNext = attr;
        *pNext = &attr->next;
    }

    *pBuffer = p;
    *pRemain = remain;

    status = GSS_S_COMPLETE;
    
cleanup:
    if (GSS_ERROR(status))
        gssint_release_name_attribute(&tmpMinor, &attr);

    return status;
}

static OM_uint32
addNameAttribute(OM_uint32 *minor_status,
                 gss_mechanism mech,
                 gss_name_t internal_name,
                 gss_buffer_t attribute_name,
                 gss_name_attribute_t *pAttr,
                 gss_name_attribute_t **pNext)
{
    gss_name_attribute_t attr = NULL;
    OM_uint32 status, tmpMinor;
    int more = -1;
    gss_buffer_set_t values, display_values;

    attr = calloc(1, sizeof(*attr));
    if (attr == NULL) {
        *minor_status = ENOMEM;
        status = GSS_S_FAILURE;
        goto cleanup;
    }

    if (!g_duplicate_buffer(attribute_name, &attr->attribute)) {
        *minor_status = ENOMEM;
        status = GSS_S_FAILURE;
        goto cleanup;
    }

    values = &attr->values;
    display_values = &attr->display_values;

    while (more != 0) {
        gss_buffer_desc value = GSS_C_EMPTY_BUFFER;
        gss_buffer_desc display_value = GSS_C_EMPTY_BUFFER;

        status = mech->gss_get_name_attribute(minor_status,
                                              internal_name,
                                              attribute_name,
                                              &attr->authenticated,
                                              &attr->complete,
                                              &value,
                                              &display_value,
                                              &more);
        if (GSS_ERROR(status))
            goto cleanup;

        status = gss_add_buffer_set_member(minor_status, &value, &values);
        if (GSS_ERROR(status)) {
            gss_release_buffer(&tmpMinor, &value);
            gss_release_buffer(&tmpMinor, &display_value);
            goto cleanup;
        }
        assert(values == &attr->values);

        status = gss_add_buffer_set_member(minor_status, &display_value,
                                           &display_values);
        if (GSS_ERROR(status)) {
            gss_release_buffer(&tmpMinor, &value);
            gss_release_buffer(&tmpMinor, &display_value);
            goto cleanup;
        }
        assert(display_values == &attr->display_values);
    }

    *pAttr = attr;

    if (pNext != NULL) {
        assert(*pNext != NULL);

        **pNext = attr;
        *pNext = &attr->next;
    }

    attr = NULL;

cleanup:
    gssint_release_name_attribute(&tmpMinor, &attr);
    return status;
}

OM_uint32
gssint_release_name_attributes(OM_uint32 *minor_status,
                               gss_name_attribute_t *pAttrs)
{
    gss_name_attribute_t attributes = *pAttrs;
    OM_uint32 tmpMinor;

    if (attributes != NULL) {
        do {
            gss_name_attribute_t next;

            next = attributes->next;
            gssint_release_name_attribute(&tmpMinor, &attributes);
            attributes = next;
        } while (attributes != NULL);

        *pAttrs = NULL;
    }

    return GSS_S_COMPLETE;
}

OM_uint32
gssint_export_internal_name_composite(OM_uint32 *minor_status,
                                      const gss_OID mech_type,
                                      const gss_name_t internal_name,
                                      gss_buffer_t name_buf)
{
    OM_uint32 status, tmpMinor;
    gss_mechanism mech;
    gss_buffer_desc expName = GSS_C_EMPTY_BUFFER;
    unsigned char *p;
    gss_buffer_set_t attrNames = GSS_C_NO_BUFFER_SET;
    gss_name_attribute_t head = NULL, attr, *pNext = &head;
    size_t i, remain;

    name_buf->length = 0;
    name_buf->value = NULL;

    mech = gssint_get_mechanism(mech_type);
    if (!mech)
        return GSS_S_BAD_MECH;

    if (mech->gss_export_name_composite) {
        status = mech->gss_export_name_composite(minor_status,
                                                 internal_name,
                                                 name_buf);
        if (status != GSS_S_COMPLETE)
            map_error(minor_status, mech);
        return status;
    }

    /*
     * If we are here it is because the mechanism does not provide
     * a gss_export_name_composite, so we will use our implementation.
     * We do require that the mechanism define a gss_inquire_name.
     *
     * We are simply going to append a serialised set of attributes
     * to the non-composite exported name and change the token ID.
     */
    if (!mech->gss_inquire_name)
        return GSS_S_UNAVAILABLE;

    status = gssint_export_internal_name(minor_status,
                                         mech_type,
                                         internal_name,
                                         &expName);
    if (GSS_ERROR(status))
        goto cleanup;

    if (expName.length < 2) {
        status = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    }

    p = (unsigned char *)expName.value;
    if (p[0] != 0x04 || p[1] != 0x01) {
        status = GSS_S_DEFECTIVE_TOKEN;
        goto cleanup;
    }

    status = mech->gss_inquire_name(minor_status,
                                    internal_name,
                                    NULL,
                                    NULL,
                                    &attrNames);
    if (status == GSS_S_UNAVAILABLE) {
        *name_buf = expName;
        return GSS_S_COMPLETE;
    } else if (GSS_ERROR(status)) {
        goto cleanup;
    }

    remain = expName.length;
    remain += 4; /* attribute count */

    for (i = 0; i < attrNames->count; i++) {
        status = addNameAttribute(minor_status,
                                  mech,
                                  internal_name,
                                  &attrNames->elements[i],
                                  &attr,
                                  &pNext);
        if (GSS_ERROR(status))
            goto cleanup;

        remain += nameAttributeSize(attr);
    }

    name_buf->value = malloc(remain);
    if (name_buf->value == NULL) {
        *minor_status = ENOMEM;
        status = GSS_S_FAILURE;
        goto cleanup;
    }
    name_buf->length = remain;

    p = (unsigned char *)name_buf->value;
    p[0] = 0x04;
    p[1] = 0x02;
    memcpy(p + 2, (unsigned char *)expName.value + 2, expName.length - 2);

    p += expName.length;
    remain -= expName.length;

    TWRITE_INT(p, attrNames->count, 1);
    remain -= 4;

    for (attr = head; attr != NULL; attr = head->next) {
        status = nameAttributeExternalize(minor_status,
                                          attr,
                                          &p,
                                          &remain);
        if (GSS_ERROR(status))
            goto cleanup;
    }

    assert(p == (unsigned char *)name_buf->value + name_buf->length);
    assert(remain == 0);

cleanup:
    if (GSS_ERROR(status))
        gss_release_buffer(&tmpMinor, name_buf);
    gss_release_buffer(&tmpMinor, &expName);
    gss_release_buffer_set(&tmpMinor, &attrNames);
    gssint_release_name_attributes(&tmpMinor, &head);

    return status;
}


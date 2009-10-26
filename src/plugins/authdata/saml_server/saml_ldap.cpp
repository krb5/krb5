/*
 * plugins/authdata/saml_server/saml_ldap.cpp
 *
 * Copyright 2009 by the Massachusetts Institute of Technology.
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
 *
 * LDAP SAML backend
 */

#include <string.h>
#include <errno.h>
#include <k5-int.h>
#include <krb5/authdata_plugin.h>
#include <kdb.h>
#include <kdb_ext.h>

#include "saml_kdc.h"

extern "C" {
#include "ldap_main.h"
#include "kdb_ldap.h"
#include "ldap_principal.h" 
#include "princ_xdr.h"
#include "ldap_err.h"
#include "ldap_schema.h"
}

static const XMLCh urnOidPrefix[] = {'u','r','n',':','o','i','d',':',0};
static const XMLCh xsdString[] = {'x','s','d',':','s','t','r','i','n','g',0};
static const XMLCh xsdBase64Binary[] = {'x','s','d',':','b','a','s','e','6','4','B','i','n','a','r','y',0};
static const XMLCh x500EncodingAttr[] = {'E','n','c','o','d','i','n','g',0};
static const XMLCh x500EncodingValue[] = {'L','D','A','P',0};


static xmltooling::QName qXsdString(XSI_NS, xsdString, XSI_PREFIX);
static xmltooling::QName qXsdBase64Binary(XSI_NS, xsdBase64Binary, XSI_PREFIX);
static xmltooling::QName qX500Encoding(SAML20X500_NS, x500EncodingAttr, SAML20X500_PREFIX);

static krb5_boolean
is_not_printable(const struct berval *bv)
{
    size_t i;

    if (isgraph(bv->bv_val[0]) &&
        isgraph(bv->bv_val[bv->bv_len - 1]))
    {
        for (i = 0; bv->bv_val[i]; i++) {
            if (!isascii(bv->bv_val[i]) || !isprint(bv->bv_val[i]))
                return TRUE;
        }
        return FALSE;
    }

    return TRUE;
}

static krb5_error_code
saml_kdc_get_attribute(krb5_context context,
                       LDAP *ld,
                       LDAPMessage *entry,
                       const char *attrname,
                       const LDAPAttributeType *attrtype,
                       saml2::Attribute **pAttr)
{
    struct berval **vals;
    Attribute *attr;
    XMLCh *canonicalName = NULL;
    auto_ptr_XMLCh oid(attrtype->at_oid);
    auto_ptr_XMLCh friendlyName(attrtype->at_names[0]);

    *pAttr = NULL;

    vals = ldap_get_values_len(ld, entry, attrname);
    if (vals == NULL || vals[0] == NULL) {
        ldap_value_free_len(vals);
        return 0;
    }

    attr = AttributeBuilder::buildAttribute();
    if (attr == NULL)
        return ENOMEM;

    canonicalName = new XMLCh[XMLString::stringLen(urnOidPrefix) +
        XMLString::stringLen(oid.get()) + 1];
    canonicalName[0] = 0;
    XMLString::catString(canonicalName, urnOidPrefix);
    XMLString::catString(canonicalName, oid.get());

    attr->setNameFormat(Attribute::URI_REFERENCE);
    attr->setName(canonicalName);
    delete canonicalName;
    attr->setFriendlyName(friendlyName.get());
    attr->setAttribute(qX500Encoding, x500EncodingValue);

    for (int i = 0; vals[i] != NULL; i++) {
        AttributeValue *value;
        struct berval *bv = vals[i];

        value = AttributeValueBuilder::buildAttributeValue();

        if (is_not_printable(bv)) {
            XMLSize_t len;
            XMLByte *b64 = Base64::encode((XMLByte *)bv->bv_val,
                                          bv->bv_len, &len);
            value->setTextContent(XMLString::transcode((char *)b64));
            delete b64;
        } else {
            auto_ptr_XMLCh unistr(bv->bv_val);
            value->setTextContent(unistr.get());
        }
        attr->getAttributeValues().push_back(value);
    }

    ldap_value_free_len(vals);

    *pAttr = attr;

    return 0;
}

krb5_error_code
saml_kdc_build_attrs_ldap(krb5_context context,
                          krb5_db_entry *client,
                          krb5_db_entry *server,
                          AttributeStatement **pAttrStatement)
{
    krb5_error_code st;
    krb5_ldap_entry *ldapent;
    LDAP *ld = NULL;
    krb5_ldap_context *ldap_context = NULL;
    krb5_ldap_server_handle *ldap_server_handle = NULL;
    saml2::AttributeStatement *attrStatement = NULL;
    char *attrname;
    BerElement *ber = NULL;
    LDAPAttributeType **attrSchema = NULL;

    *pAttrStatement = NULL;

    ldapent = (krb5_ldap_entry *)client->e_data;
    if (client->e_length != sizeof(*ldapent) ||
        ldapent->magic != KRB5_LDAP_ENTRY_MAGIC) {
        return EINVAL;
    }

    ldap_context = (krb5_ldap_context *)context->dal_handle->db_context;
    CHECK_LDAP_HANDLE(ldap_context);
    GET_HANDLE();

    st = krb5_ldap_get_entry_attrtypes(context, ldap_context,
                                       ldap_server_handle, ld,
                                       ldapent->entry, &attrSchema);
    if (st != 0)
        goto cleanup;

    attrStatement = AttributeStatementBuilder::buildAttributeStatement();
    attrStatement->addNamespace(Namespace(SAML20X500_NS, SAML20X500_PREFIX));

    for (attrname = ldap_first_attribute(ld, ldapent->entry, &ber);
         attrname != NULL;
         attrname = ldap_next_attribute(ld, ldapent->entry, ber)) {
        Attribute *attr;
        const LDAPAttributeType *attrtype;

        attrtype = krb5_ldap_find_attrtype(attrSchema, attrname);
        if (attrtype == NULL ||
            strcasecmp(attrname, "subschemaSubentry") == 0 ||
            krb5_ldap_is_kerberos_attr(attrname)) {
            ldap_memfree(attrname);
            continue;
        }

        saml_kdc_get_attribute(context, ld, ldapent->entry,
                               attrname, attrtype, &attr);

        if (attr != NULL)
            attrStatement->getAttributes().push_back(attr);
        ldap_memfree(attrname);
    }

    *pAttrStatement = attrStatement;
    attrStatement = NULL;

cleanup:
    krb5_ldap_free_entry_attrtypes(attrSchema);
    krb5_ldap_put_handle_to_pool(ldap_context, ldap_server_handle);
    delete attrStatement;

    return st;
}


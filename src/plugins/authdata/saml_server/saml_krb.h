/*
 * plugins/authdata/saml_server/saml_krb.h
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
 * SAML Kerberos helpers
 */

#ifndef SAML_KRB_H_
#define SAML_KRB_H_ 1

extern "C" {
#include <k5-int.h>
#include <krb5/authdata_plugin.h>
#include <kdb.h>
#include <kdb_ext.h>
}

#include <saml/SAMLConfig.h>
#include <saml/saml2/metadata/Metadata.h>
#include <saml/saml2/metadata/MetadataProvider.h>
#include <saml/saml2/metadata/MetadataCredentialCriteria.h>
#include <saml/signature/SignatureProfileValidator.h>
#include <saml/util/SAMLConstants.h>
#include <xmltooling/logging.h>
#include <xmltooling/XMLToolingConfig.h>
#include <xmltooling/security/SignatureTrustEngine.h>
#include <xmltooling/security/OpenSSLCredential.h>
#include <xmltooling/signature/Signature.h>
#include <xmltooling/signature/SignatureValidator.h>
#include <xmltooling/util/XMLHelper.h>
#include <xsec/framework/XSECException.hpp>
#include <xsec/dsig/DSIGKeyInfoValue.hpp>
#include <xsec/dsig/DSIGKeyInfoName.hpp>
#include <xsec/enc/XSECCryptoKeyHMAC.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyHMAC.hpp>
#include <xercesc/util/Base64.hpp>

using namespace xmlsignature;
using namespace xmlconstants;
using namespace xmltooling::logging;
using namespace xmltooling;
using namespace samlconstants;
using namespace opensaml::saml2md;
using namespace opensaml::saml2;
using namespace opensaml;
using namespace xercesc;
using namespace std;

#define SAML_KRB_VERIFY_SESSION_KEY     0x1 /* signed with session key */
#define SAML_KRB_VERIFY_TRUSTENGINE     0x2 /* signed with trusted key */
#define SAML_KRB_VERIFY_KDC_VOUCHED     0x4 /* extracted from TGT */

#define SAML_KRB_USAGE_SESSION_KEY      1   /* derive from session key */
#define SAML_KRB_USAGE_SERVER_KEY       2   /* derive from server key */

krb5_error_code
saml_krb_derive_key(krb5_context context,
                    const krb5_keyblock *basekey,
                    unsigned int usage,
                    XSECCryptoKey **pXMLKey);

krb5_boolean
saml_krb_is_saml_principal(krb5_context context,
                           krb5_const_principal principal);

krb5_error_code
saml_krb_unparse_name_xmlch(krb5_context context,
                            krb5_const_principal name,
                            XMLCh **unicodePrincipal,
                            int flags = 0);

krb5_error_code
saml_krb_parse_name_xmlch(krb5_context context,
                          const XMLCh *unicodePrincipal,
                          krb5_principal *name,
                          int flags = 0);

krb5_error_code
saml_krb_build_nameid(krb5_context context,
                      krb5_const_principal principal,
                      NameID **pNameID);

krb5_boolean
saml_krb_compare_principal(krb5_context context,
                           const XMLCh *unicodePrincipal,
                           krb5_const_principal princ1);

krb5_error_code
saml_krb_map_subject(krb5_context context,
                     Subject *subject,
                     krb5_principal *pMappedPrincipal);

krb5_boolean
saml_krb_compare_issuer(krb5_context context,
                        Issuer *asserted,
                        Issuer *actual);

krb5_boolean
saml_krb_compare_subject(krb5_context context,
                         Subject *asserted,
                         Subject *actual);

krb5_error_code
saml_krb_bind_subject_kdb(krb5_context context,
                          krb5_db_entry *entry,
                          Issuer *issuer,
                          Subject *subject);

krb5_timestamp
saml_krb_get_authtime(krb5_context context,
                      const saml2::Assertion *assertion);

krb5_error_code
saml_krb_build_principal_keyinfo(krb5_context context,
                                 krb5_const_principal principal,
                                 KeyInfo **pKeyInfo);

krb5_error_code
saml_krb_confirm_keyinfo(krb5_context context,
                         const saml2::SubjectConfirmation *conf,
                         krb5_const_principal principal,
                         krb5_boolean *pConfirmed);

krb5_error_code
saml_krb_confirm_subject(krb5_context context,
                         const saml2::Subject *subject,
                         krb5_const_principal principal,
                         krb5_timestamp authtime,
                         krb5_boolean *pConfirmed,
                         krb5_boolean *pBound);

krb5_error_code
saml_krb_verify_recipient(krb5_context context,
                          const saml2::Assertion *assertion,
                          krb5_const_principal spn,
                          krb5_boolean *pValid);

krb5_error_code
saml_krb_verify_signature(krb5_context context,
                          Signature *signature,
                          const krb5_keyblock *key,
                          unsigned int flags,
                          krb5_boolean bound,
                          krb5_boolean *pValid);

krb5_error_code
saml_krb_bind_subject(krb5_context context,
                      Issuer *issuer,
                      Subject *subject,
                      krb5_const_principal client_princ,
                      krb5_db_entry *client,
                      krb5_boolean *pBound,
                      krb5_principal *pMappedPrincipal = NULL);

krb5_error_code
saml_krb_verify(krb5_context context,
                saml2::Assertion *assertion,
                const krb5_keyblock *key,
                krb5_const_principal client_princ,
                krb5_db_entry *client,
                krb5_const_principal server,
                krb5_timestamp authtime,
                unsigned int flags,
                krb5_boolean *pValid,
                krb5_principal *pMappedPrincipal = NULL);

krb5_error_code
saml_krb_decode_assertion(krb5_context context,
                          krb5_data *data,
                          saml2::Assertion **pAssertion);

krb5_error_code
saml_krb_decode_assertion(krb5_context context,
                          krb5_authdata *data,
                          saml2::Assertion **pAssertion);

/* Helper for transcoding krb5_data objects */
class auto_ptr_krb5_data {
    MAKE_NONCOPYABLE(auto_ptr_krb5_data);
    public:
        auto_ptr_krb5_data() : m_buf(NULL) {
        }
        auto_ptr_krb5_data(const krb5_data *src) {
            m_buf = new XMLCh[src->length + 1];
            XMLString::transcode(src->data, m_buf, src->length);
        }
        ~auto_ptr_krb5_data() {
            xercesc::XMLString::release(&m_buf);
        }
        const XMLCh* get() const {
            return m_buf;
        }
        XMLCh* release() {
            XMLCh *temp = m_buf; m_buf = NULL; return temp;
        }
    private:
        XMLCh *m_buf;
};

#endif /* SAML_KRB_H_ */


/*
 * Copyright (C) 2011-2018 PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "gssapiP_negoex.h"

static void
negoex_release_cred(negoex_cred_id_t cred)
{
    OM_uint32 tmpMinor;

    if (cred == NULL)
        return;

    gss_release_cred(&tmpMinor, &cred->Credential);
    gss_release_oid_set(&tmpMinor, &cred->NegMechs);
    negoex_free(cred);
}

static OM_uint32
negoex_alloc_cred(OM_uint32 *minor,
                  negoex_cred_id_t *pCred)
{
    OM_uint32 major;

    *pCred = negoex_calloc(&major, minor, 1, sizeof(negoex_cred_id_rec));
    if (GSS_ERROR(major))
        return major;

    return GSS_S_COMPLETE;
}

static OM_uint32
negoex_acquire_cred_common(OM_uint32 *minor,
                           const gss_name_t desiredName,
                           const gss_buffer_t password,
                           OM_uint32 timeReq,
                           gss_cred_usage_t usage,
                           gss_const_key_value_set_t credStore,
                           gss_cred_id_t *pCreds,
                           gss_OID_set *pCredMechs,
                           OM_uint32 *pTimeRec)
{
    OM_uint32 major, tmpMinor;
    gss_OID_set mechs;
    gss_OID_set availableMechs = GSS_C_NO_OID_SET;
    ULONG i;

    assert(*pCreds == GSS_C_NO_CREDENTIAL);

    major = gss_indicate_mechs(minor, &mechs);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_create_empty_oid_set(minor, &availableMechs);
    if (GSS_ERROR(major))
        goto cleanup;

    for (i = 0; i < mechs->count; i++) {
        gss_OID thisMech = &mechs->elements[i];
        AUTH_SCHEME authScheme;

        if (!GSS_ERROR(gss_query_mechanism_info(minor,
                                                thisMech,
                                                authScheme))) {
            major = gss_add_oid_set_member(minor,
                                           thisMech,
                                           &availableMechs);
            if (GSS_ERROR(major))
                goto cleanup;
        }
    }

    if (availableMechs == 0) {
        major = GSS_S_NO_CRED;
        *minor = NEGOEX_NO_AVAILABLE_MECHS;
        goto cleanup;
    }

    if (password != NULL) {
        major = gss_acquire_cred_with_password(minor,
                                               desiredName,
                                               password,
                                               timeReq,
                                               availableMechs,
                                               usage,
                                               pCreds,
                                               pCredMechs,
                                               pTimeRec);
    } else {
        major = gss_acquire_cred_from(minor,
                                      desiredName,
                                      timeReq,
                                      availableMechs,
                                      usage,
                                      credStore,
                                      pCreds,
                                      pCredMechs,
                                      pTimeRec);
    }
    if (GSS_ERROR(major))
        goto cleanup;

cleanup:
    fprintf(stderr, "*** Acquire creds negoex %d\n", major);
    gss_release_oid_set(&tmpMinor, &availableMechs);

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_acquire_cred(OM_uint32 *minor,
                        const gss_name_t desired_name,
                        OM_uint32 time_req,
                        const gss_OID_set desired_mechs,
                        int cred_usage,
                        gss_cred_id_t *output_cred_handle,
                        gss_OID_set *actual_mechs,
                        OM_uint32 *time_rec)
{
    return negoex_gss_acquire_cred_from(minor,
                                        desired_name,
                                        time_req,
                                        desired_mechs,
                                        cred_usage,
                                        GSS_C_NO_CRED_STORE,
                                        output_cred_handle,
                                        actual_mechs,
                                        time_rec);

}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_acquire_cred_with_password(OM_uint32 *minor,
                                      const gss_name_t desired_name,
                                      const gss_buffer_t password,
                                      OM_uint32 time_req,
                                      const gss_OID_set desired_mechs,
                                      gss_cred_usage_t cred_usage,
                                      gss_cred_id_t *output_cred_handle,
                                      gss_OID_set *actual_mechs,
                                      OM_uint32 *time_rec)
{
    OM_uint32 major;
    negoex_cred_id_t cred = NULL;

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (actual_mechs != NULL)
        *actual_mechs = GSS_C_NO_OID_SET;
    if (time_rec != NULL)
        *time_rec = 0;

    major = negoex_alloc_cred(minor, &cred);
    if (GSS_ERROR(major))
        return major;

    major = negoex_acquire_cred_common(minor, desired_name, password,
                                       time_req, cred_usage, NULL,
                                       &cred->Credential,
                                       actual_mechs, time_rec);
    if (GSS_ERROR(major)) {
        negoex_release_cred(cred);
        return major;
    }

    *output_cred_handle = (gss_cred_id_t)cred;

    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_acquire_cred_from(OM_uint32 *minor,
                             const gss_name_t desired_name,
                             OM_uint32 time_req,
                             const gss_OID_set desired_mechs,
                             gss_cred_usage_t cred_usage,
                             gss_const_key_value_set_t cred_store,
                             gss_cred_id_t *output_cred_handle,
                             gss_OID_set *actual_mechs,
                             OM_uint32 *time_rec)
{
    OM_uint32 major;
    negoex_cred_id_t cred = NULL;

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (actual_mechs != NULL)
        *actual_mechs = GSS_C_NO_OID_SET;
    if (time_rec != NULL)
        *time_rec = 0;

    major = negoex_alloc_cred(minor, &cred);
    if (GSS_ERROR(major))
        return major;

    major = negoex_acquire_cred_common(minor, desired_name, NULL,
                                       time_req, cred_usage,
                                       cred_store, &cred->Credential,
                                       actual_mechs, time_rec);
    if (GSS_ERROR(major)) {
        negoex_release_cred(cred);
        return major;
    }

    *output_cred_handle = (gss_cred_id_t)cred;

    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_release_cred(OM_uint32 *minor,
                        gss_cred_id_t *cred)
{
    if (cred != NULL)
        negoex_release_cred((negoex_cred_id_t)*cred);

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_cred(OM_uint32 *minor,
                        gss_cred_id_t cred_handle,
                        gss_name_t *pName,
                        OM_uint32 *pLifetime,
                        gss_cred_usage_t *pCredUsage,
                        gss_OID_set *pMechanisms)
{
    OM_uint32 major, tmpMinor;
    negoex_cred_id_t cred = (negoex_cred_id_t)cred_handle;
    gss_cred_id_t tmpCred = GSS_C_NO_CREDENTIAL;
    gss_OID_set mechs = GSS_C_NO_OID_SET;
    gss_cred_usage_t credUsage;
    OM_uint32 initiatorLifetime, acceptorLifetime;

    if (pName != NULL)
        *pName = GSS_C_NO_NAME;
    if (pLifetime != NULL)
        *pLifetime = 0;
    if (pCredUsage != NULL)
        *pCredUsage = 0;
    if (pMechanisms != NULL)
        *pMechanisms = GSS_C_NO_OID_SET;

    if (cred == NULL)
        return GSS_S_FAILURE;

    if (cred->Credential != GSS_C_NO_CREDENTIAL)
        return gss_inquire_cred(minor,
                                cred->Credential,
                                pName,
                                pLifetime,
                                pCredUsage,
                                pMechanisms);

    major = negoex_acquire_cred_common(minor,
                                       GSS_C_NO_NAME,
                                       NULL,
                                       GSS_C_INDEFINITE,
                                       GSS_C_BOTH,
                                       NULL,
                                       &tmpCred,
                                       &mechs,
                                       NULL);
    if (GSS_ERROR(major))
        return major;

    if (mechs == GSS_C_NO_OID_SET || mechs->count == 0) {
        /* shouldn't happen, but this comes direct from mechglue */
        *minor = NEGOEX_NO_AVAILABLE_MECHS;
        gss_release_oid_set(&tmpMinor, &mechs);
        return GSS_S_DEFECTIVE_CREDENTIAL;
    }

    /* SPNEGO only inquires the first cred, let's do that too */
    major = gss_inquire_cred_by_mech(minor,
                                     tmpCred,
                                     &mechs->elements[0],
                                     pName,
                                     &initiatorLifetime,
                                     &acceptorLifetime,
                                     &credUsage);
    if (major == GSS_S_COMPLETE) {
        if (pLifetime != NULL)
            *pLifetime = credUsage == GSS_C_ACCEPT ?
                                      acceptorLifetime : initiatorLifetime;
        if (pCredUsage != NULL)
            *pCredUsage = credUsage;
        if (pMechanisms != NULL) {
            *pMechanisms = mechs;
            mechs = GSS_C_NO_OID_SET;
        }
    }

    gss_release_cred(&tmpMinor, &tmpCred);
    gss_release_oid_set(&tmpMinor, &mechs);

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_inquire_cred_by_oid(OM_uint32 *minor,
                               const gss_cred_id_t cred_handle,
                               const gss_OID desired_object,
                               gss_buffer_set_t *data_set)
{
    negoex_cred_id_t cred = (negoex_cred_id_t)cred_handle;
    gss_cred_id_t mechCred = cred ? cred->Credential : GSS_C_NO_CREDENTIAL;

    return gss_inquire_cred_by_oid(minor, mechCred, desired_object, data_set);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_set_cred_option(OM_uint32 *minor,
                           gss_cred_id_t *cred_handle,
                           const gss_OID desired_object,
                           const gss_buffer_t value)
{
    OM_uint32 major, tmpMinor;
    negoex_cred_id_t cred = (negoex_cred_id_t)*cred_handle;
    gss_cred_id_t mechCred = cred ? cred->Credential : GSS_C_NO_CREDENTIAL;

    major = gss_set_cred_option(minor, &mechCred,
                                desired_object, value);

    if (major == GSS_S_COMPLETE && cred == NULL) {
        major = negoex_alloc_cred(minor, &cred);
        if (GSS_ERROR(major)) {
            gss_release_cred(&tmpMinor, &mechCred);
            return major;
        }
        cred->Credential = mechCred;
        *cred_handle = (gss_cred_id_t)cred;
    }

    return major;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_set_neg_mechs(OM_uint32 *minor,
                         gss_cred_id_t cred_handle,
                         const gss_OID_set mech_list)
{
    negoex_cred_id_t cred = (negoex_cred_id_t)cred_handle;

    gss_release_oid_set(minor, &cred->NegMechs);

    return generic_gss_copy_oid_set(minor, mech_list, &cred->NegMechs);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_store_cred(OM_uint32 *minor,
                      gss_cred_id_t input_cred,
                      gss_cred_usage_t cred_usage,
                      const gss_OID desired_mech,
                      OM_uint32 overwrite_cred,
                      OM_uint32 default_cred,
                      gss_OID_set *elements_stored,
                      gss_cred_usage_t *cred_usage_stored)
{
    negoex_cred_id_t cred = (negoex_cred_id_t)input_cred;
    gss_cred_id_t mechCred = cred ? cred->Credential : GSS_C_NO_CREDENTIAL;

    return gss_store_cred(minor, mechCred, cred_usage, desired_mech,
                          overwrite_cred, default_cred, elements_stored,
                          cred_usage_stored);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_store_cred_into(OM_uint32 *minor,
                           gss_cred_id_t input_cred,
                           gss_cred_usage_t cred_usage,
                           const gss_OID desired_mech,
                           OM_uint32 overwrite_cred,
                           OM_uint32 default_cred,
                           gss_const_key_value_set_t cred_store,
                           gss_OID_set *elements_stored,
                           gss_cred_usage_t *cred_usage_stored)
{
    negoex_cred_id_t cred = (negoex_cred_id_t)input_cred;
    gss_cred_id_t mechCred = cred ? cred->Credential : GSS_C_NO_CREDENTIAL;

    return gss_store_cred_into(minor, mechCred, cred_usage, desired_mech,
                               overwrite_cred, default_cred, cred_store,
                               elements_stored, cred_usage_stored);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_export_cred(OM_uint32 *minor,
                       gss_cred_id_t cred_handle,
                       gss_buffer_t token)
{
    negoex_cred_id_t cred = (negoex_cred_id_t)cred_handle;
    gss_cred_id_t mechCred = cred ? cred->Credential : GSS_C_NO_CREDENTIAL;

    return gss_export_cred(minor, mechCred, token);
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_import_cred(OM_uint32 *minor,
                       gss_buffer_t token,
                       gss_cred_id_t *cred_handle)
{
    OM_uint32 major;
    negoex_cred_id_t cred;
    gss_cred_id_t mechCred = GSS_C_NO_CREDENTIAL;

    major = negoex_alloc_cred(minor, &cred);
    if (GSS_ERROR(major))
        return major;

    major = gss_import_cred(minor, token, &mechCred);
    if (GSS_ERROR(major)) {
        negoex_release_cred(cred);
        return major;
    }

    cred->Credential = mechCred;
    *cred_handle = (gss_cred_id_t)cred;

    *minor = 0;
    return GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
negoex_gss_acquire_cred_impersonate_name(OM_uint32 *minor,
                                         const gss_cred_id_t impersonator_cred_handle,
                                         const gss_name_t desired_name,
                                         OM_uint32 time_req,
                                         gss_OID_set desired_mechs,
                                         gss_cred_usage_t cred_usage,
                                         gss_cred_id_t *output_cred_handle,
                                         gss_OID_set *actual_mechs,
                                         OM_uint32 *time_rec)
{
    OM_uint32 major, tmpMinor;
    negoex_cred_id_t impCred = (negoex_cred_id_t)impersonator_cred_handle;
    gss_cred_id_t impMechCred = impCred ? impCred->Credential : GSS_C_NO_CREDENTIAL;
    negoex_cred_id_t outCred = NULL;
    gss_cred_id_t outMechCred = GSS_C_NO_CREDENTIAL;
    gss_OID_set mechs = GSS_C_NO_OID_SET;

    *output_cred_handle = GSS_C_NO_CREDENTIAL;
    if (actual_mechs != NULL)
        *actual_mechs = GSS_C_NO_OID_SET;
    if (time_rec != NULL)
        *time_rec = 0;

    major = negoex_alloc_cred(minor, &outCred);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_inquire_cred(minor, impMechCred, NULL, NULL, NULL, &mechs);
    if (GSS_ERROR(major))
        goto cleanup;

    major = gss_acquire_cred_impersonate_name(minor,
                                              impMechCred,
                                              desired_name,
                                              time_req,
                                              mechs,
                                              cred_usage,
                                              &outMechCred,
                                              actual_mechs,
                                              time_rec);
    if (GSS_ERROR(major))
        goto cleanup;

    outCred->Credential = outMechCred;

    *output_cred_handle = (gss_cred_id_t)outCred;
    outCred = NULL;

cleanup:
    gss_release_oid_set(&tmpMinor, &mechs);
    negoex_release_cred(outCred);

    return major;
}

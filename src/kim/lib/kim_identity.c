/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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

#include "k5-int.h"
#include <krb5.h>
#include "kim_private.h"

/* ------------------------------------------------------------------------ */

struct kim_identity_opaque {
    krb5_context          context;
    krb5_principal        principal;
};

struct kim_identity_opaque kim_identity_initializer = { NULL, NULL };

/* ------------------------------------------------------------------------ */

static inline kim_error kim_identity_allocate (kim_identity *out_identity)
{
    kim_error err = kim_library_init ();
    kim_identity identity = NULL;
    
    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        identity = malloc (sizeof (*identity));
        if (!identity) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        *identity = kim_identity_initializer;
        *out_identity = identity;
        identity = NULL;
    }
    
    kim_identity_free (&identity);
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_create_from_string (kim_identity *out_identity,
                                           kim_string    in_string)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    
    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_string   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_allocate (&identity);
    }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&identity->context));
    }
    
    if (!err) {
        krb5_error_code code = krb5_parse_name (identity->context, in_string, &identity->principal);
        if (code == KRB5_PARSE_MALFORMED) {
            err = kim_error_set_message_for_code (KIM_BAD_PRINCIPAL_STRING_ERR, 
                                                  in_string);
        } else if (code) {
            err = krb5_error (identity->context, code);
        }
    }
    
    if (!err) {
        *out_identity = identity;
        identity = NULL;
    }
    
    if (identity) { kim_identity_free (&identity); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_create_from_components (kim_identity *out_identity,
                                               kim_string    in_realm, 
                                               kim_string    in_1st_component,
                                               ...)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    
    if (!err && !out_identity    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_realm        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_1st_component) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_allocate (&identity);
    }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&identity->context));
    }
    
    if (!err) {
        va_list args;

        va_start (args, in_1st_component);
        err = krb5_error (identity->context,
                          krb5int_build_principal_alloc_va (identity->context,
                                                            &identity->principal,
                                                            strlen(in_realm),
                                                            in_realm,
                                                            in_1st_component,
                                                            args));
        va_end (args);
    }   

    if (!err) {
        *out_identity = identity;
        identity = NULL;
    }
    
    kim_identity_free (&identity);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_create_from_krb5_principal (kim_identity  *out_identity,
                                                   krb5_context   in_krb5_context,
                                                   krb5_principal in_krb5_principal)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = NULL;
    
    if (!err && !out_identity     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_krb5_principal) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    /* KLCreatePrincipalFromKerberos5Principal passes NULL in_krb5_context */
    
    if (!err) {
        err = kim_identity_allocate (&identity);
    }
    
    if (!err) {
        if (in_krb5_context) {
            err = krb5_error (in_krb5_context, 
                              krb5_copy_context (in_krb5_context,
                                                 &identity->context));
        } else {
            err = krb5_error (NULL, 
                              krb5_init_context (&identity->context));
        }
    }
    
    if (!err) {
        err = krb5_error (identity->context,
                          krb5_copy_principal (identity->context, 
                                               in_krb5_principal, 
                                               &identity->principal));
    }
    
    if (!err) {
        *out_identity = identity;
        identity = NULL;
    }
    
    kim_identity_free (&identity);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_copy (kim_identity *out_identity,
                             kim_identity  in_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity identity = KIM_IDENTITY_ANY;
    
    if (!err && !out_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err && in_identity != KIM_IDENTITY_ANY) {
        err = kim_identity_allocate (&identity);
        
        if (!err) {
            err = krb5_error (in_identity->context, 
                              krb5_copy_context (in_identity->context,
                                                 &identity->context));
        }
        
        if (!err) {
            err = krb5_error (identity->context,
                              krb5_copy_principal (identity->context, 
                                                   in_identity->principal, 
                                                   &identity->principal));
        }
    }
    
    if (!err) {
        *out_identity = identity;
        identity = NULL;
    }
    
    kim_identity_free (&identity);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_compare (kim_identity    in_identity,
                                kim_identity    in_compare_to_identity,
                                kim_comparison *out_comparison)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_identity           ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_compare_to_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_comparison        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        if (krb5_principal_compare (in_identity->context, 
                                    in_identity->principal, 
                                    in_compare_to_identity->principal)) {
            *out_comparison = 0;
        } else {
            kim_string string = NULL;
            kim_string compare_to_string = NULL;
            
            err = kim_identity_get_string (in_identity, &string);
            
            if (!err) {
                err = kim_identity_get_string (in_compare_to_identity, &compare_to_string);
            }
            
            if (!err) {
                err = kim_string_compare (string, compare_to_string, out_comparison);
            }
            
            kim_string_free (&string);
            kim_string_free (&compare_to_string);
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_get_string (kim_identity   in_identity,
                                   kim_string    *out_string)
{
    kim_error err = KIM_NO_ERROR;
    char *unparsed_name = NULL;
    
    if (!err && !in_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_string ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = krb5_error (in_identity->context,
                          krb5_unparse_name (in_identity->context, 
                                             in_identity->principal, 
                                             &unparsed_name));
    }
    
    if (!err) {
        err = kim_string_copy (out_string, unparsed_name);
    }
    
    if (unparsed_name) { krb5_free_unparsed_name (in_identity->context, unparsed_name); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_get_display_string (kim_identity   in_identity,
                                           kim_string    *out_display_string)
{
    kim_error err = KIM_NO_ERROR;
    kim_string string = NULL;
    
    if (!err && !in_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_display_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_get_string (in_identity, &string);
    }
    
    if (!err) {
        kim_count i, j;
        kim_count length = strlen (string) + 1; /* Copy the '\0' */
        char *display_string = (char *) string; /* so we can modify it */
        
        /* In place copy, skipping escaped separators.
         * Note that we do not want to remove other escaped characters
         * (tab, break, newline, NULL) because they are less readable 
         * when unescaped (and NULL isn't a valid string character).  */
        for (i = 0, j = 0; i < length; i++) {
            if (string[i] == '\\') {
                switch (string[i + 1]) {
                    case '/': /* component separator */
                    case '@': /* realm separator */
                        continue; /* skip the '\' */
                }
            }
            
            display_string[j++] = string[i]; /* Copy this char */
        } 
        
        *out_display_string = string;
        string = NULL;
    }
    
    if (string) { kim_string_free (&string); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_get_realm (kim_identity  in_identity,
                                  kim_string   *out_realm_string)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_identity     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_realm_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        krb5_data *realm = krb5_princ_realm (in_identity->context, in_identity->principal);
        
        err = kim_string_create_from_buffer (out_realm_string, realm->data, realm->length);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_get_number_of_components (kim_identity  in_identity,
                                                 kim_count    *out_number_of_components)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_identity             ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_number_of_components) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_number_of_components = krb5_princ_size (in_identity->context, in_identity->principal);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_get_component_at_index (kim_identity  in_identity,
                                               kim_count     in_index,
                                               kim_string   *out_component_string)
{
    kim_error err = KIM_NO_ERROR;
    krb5_data *component = NULL;
    
    if (!err && !in_identity         ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_component_string) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        krb5_int32 i = in_index;
        component = krb5_princ_component (in_identity->context, in_identity->principal, i);
        if (!component) { 
            err = kim_error_set_message_for_code (KIM_BAD_COMPONENT_INDEX_ERR, i); 
        }
    }
    
    if (!err) {
        err = kim_string_create_from_buffer (out_component_string, component->data, component->length);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_get_components_string (kim_identity  in_identity,
                                              kim_string   *out_components)
{
    kim_error err = KIM_NO_ERROR;
    kim_string components = NULL;
    kim_count count, i;
    
    if (!err && !in_identity   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_components) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_get_number_of_components (in_identity, &count);
    }
    
    if (!err) {
        err = kim_identity_get_component_at_index (in_identity, 0, &components);
    }
    
    for (i = 1; !err && i < count; i++) {
        kim_string new_components = NULL;
        kim_string component = NULL;
        
        err = kim_identity_get_component_at_index (in_identity, i, &component);
        
        if (!err) {
            err = kim_string_create_from_format (&new_components, "%s/%s",
                                                 components, component);
        }
        
        if (!err) {
            kim_string_free (&components);
            components = new_components;
            new_components = NULL;
        }
        
        if (component     ) { kim_string_free (&component); }
        if (new_components) { kim_string_free (&new_components); }
    }
    
    if (!err) {
        *out_components = components;
        components = NULL;
    }
    
    if (components) { kim_string_free (&components); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_get_krb5_principal (kim_identity    in_identity,
                                           krb5_context    in_krb5_context,
                                           krb5_principal *out_krb5_principal)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_krb5_context   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_krb5_principal) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = krb5_error (in_krb5_context,
                          krb5_copy_principal (in_krb5_context, 
                                               in_identity->principal, 
                                               out_krb5_principal));
    }    
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

krb5_principal kim_identity_krb5_principal (kim_identity in_identity)
{
    if (in_identity) {
        return in_identity->principal;
    }
    check_error (KIM_NULL_PARAMETER_ERR); /* log error */
    return NULL;
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_is_tgt_service (kim_identity  in_identity,
                                       kim_boolean  *out_is_tgt_service)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_identity       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_is_tgt_service) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_count count = krb5_princ_size (in_identity->context, in_identity->principal);
        krb5_data *name = krb5_princ_name (in_identity->context, in_identity->principal);
        
        /* krbtgt/<REALM1>@<REALM2> (usually REALM1 == REALM2, but not always) */
        *out_is_tgt_service = ((count == 2) &&
                               (strlen (KRB5_TGS_NAME) == name->length) &&
                               (strncmp (name->data, KRB5_TGS_NAME, name->length) == 0));
    }
    
    return check_error (err);
}


/* ------------------------------------------------------------------------ */

kim_error kim_identity_change_password_with_credential (kim_identity    in_identity,
                                                        kim_credential  in_credential,
                                                        kim_string      in_new_password,
                                                        kim_ui_context *in_ui_context,
                                                        kim_error      *out_rejected_err,
                                                        kim_string     *out_rejected_message,
                                                        kim_string     *out_rejected_description)
{
    kim_error err = KIM_NO_ERROR;
    krb5_creds *creds = NULL;
    int rejected_err = 0;
    krb5_data message_data;
    krb5_data description_data;
    
    if (!err && !in_identity     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_credential   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_new_password ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_ui_context   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_rejected_err) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_credential_get_krb5_creds (in_credential,
                                             in_identity->context,
                                             &creds);
    }

    if (!err) {
        if (krb5_principal_compare (in_identity->context, 
                                    in_identity->principal,
                                    creds->client)) {
            /* Same principal, change the password normally */
            err = krb5_error (in_identity->context,
                              krb5_change_password (in_identity->context, 
                                                    creds, 
                                                    (char *) in_new_password, 
                                                    &rejected_err, 
                                                    &message_data, 
                                                    &description_data));
        } else {
            /* Different principal, use set change password protocol */
            err = krb5_error (in_identity->context,
                              krb5_set_password (in_identity->context, 
                                                 creds, 
                                                 (char *) in_new_password, 
                                                 in_identity->principal,
                                                 &rejected_err, 
                                                 &message_data, 
                                                 &description_data));
        }
        
    }
    
    if (!err && rejected_err) {
        kim_string rejected_message = NULL;
        kim_string rejected_description = NULL;
        
        if (message_data.data && message_data.length > 0) {
            err = kim_string_create_from_buffer (&rejected_message, 
                                                 message_data.data, 
                                                 message_data.length);
        } else {
            err = kim_os_string_create_localized (&rejected_message,
                                                  "Kerberos Change Password Failed:");
        }
        
        if (!err) {
            if (description_data.data && description_data.length > 0) {
                err = kim_string_create_from_buffer (&rejected_description,
                                                     description_data.data, 
                                                     description_data.length);
            } else {
                err = kim_os_string_create_localized (&rejected_description,
                                                      "New password rejected.");
            }
        }
        
        if (!err && in_ui_context->type != kim_ui_type_cli) {
            char *c;
            
            // replace all \n and \r characters with spaces
            for (c = (char *) rejected_message; *c != '\0'; c++) {
                if ((*c == '\n') || (*c == '\r')) { *c = ' '; }
            }
            
            for (c = (char *) rejected_description; *c != '\0'; c++) {
                if ((*c == '\n') || (*c == '\r')) { *c = ' '; }
            }
        }
        
        if (!err) {
            if (out_rejected_message) {
                *out_rejected_message = rejected_message;
                rejected_message = NULL;
            }
            if (out_rejected_description) {
                *out_rejected_description = rejected_description;
                rejected_description = NULL;
            }
        }
        
        kim_string_free (&rejected_message);
        kim_string_free (&rejected_description);
        
        krb5_free_data_contents (in_identity->context, &message_data);
        krb5_free_data_contents (in_identity->context, &description_data);
    }
    
    if (!err) {
        /* do this after reporting errors so we don't double report rejection */
        *out_rejected_err = rejected_err;
    }
    
    if (creds) { krb5_free_creds (in_identity->context, creds); }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_change_password_common (kim_identity    in_identity,
                                               kim_boolean     in_old_password_expired,
                                               kim_ui_context *in_ui_context,
                                               kim_string     *out_new_password)
{
    kim_error err = KIM_NO_ERROR;
    kim_boolean done = 0;
    
    if (!err && !in_identity  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_ui_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    while (!err && !done) {
        char *old_password = NULL;
        char *new_password = NULL;
        char *verify_password = NULL;
        kim_error rejected_err = KIM_NO_ERROR;
        kim_string rejected_message = NULL;
        kim_string rejected_description = NULL;
        kim_boolean was_prompted = 0;   /* ignore because we always prompt */
        
        err = kim_ui_change_password (in_ui_context,
                                      in_identity,
                                      in_old_password_expired,
                                      &old_password,
                                      &new_password,
                                      &verify_password);
        
        if (!err) {
            kim_comparison comparison;
            
            err = kim_string_compare (new_password, 
                                      verify_password, 
                                      &comparison);
            if (!err && !kim_comparison_is_equal_to (comparison)) {
                err = check_error (KIM_PASSWORD_MISMATCH_ERR);
            }
        }
        
        if (!err) {
            kim_credential credential = NULL;
            
            if (in_ui_context->type == kim_ui_type_cli && in_ui_context->tcontext) {
                /* command line has already gotten the credentials for us */
                credential = (kim_credential) in_ui_context->tcontext;
            } else {
                err = kim_credential_create_for_change_password (&credential,
                                                                 in_identity,
                                                                 old_password,
                                                                 in_ui_context,
                                                                 &was_prompted);
            }
            
            if (!err) {
                err = kim_identity_change_password_with_credential (in_identity,
                                                                    credential, 
                                                                    new_password,
                                                                    in_ui_context,
                                                                    &rejected_err,
                                                                    &rejected_message,
                                                                    &rejected_description);
            }  
            
            kim_credential_free (&credential);
            if (in_ui_context->type == kim_ui_type_cli) { 
                in_ui_context->tcontext = NULL; /* just freed our creds */
            }
        }
        
        if (!err && rejected_err) {
            /* Password rejected, report it to the user */
            err = kim_ui_handle_error (in_ui_context, in_identity,
                                       rejected_err,
                                       rejected_message, 
                                       rejected_description);
            
        } else if (err && err != KIM_USER_CANCELED_ERR && 
                          err != KIM_DUPLICATE_UI_REQUEST_ERR) {
            /* New creds failed, report error to user.
             * Overwrite error so we loop and let the user try again.
             * The user always gets prompted so we always loop. */
            err = kim_ui_handle_kim_error (in_ui_context, in_identity, 
                                           kim_ui_error_type_change_password,
                                           err);
            
        } else {
            /* password change succeeded or the user gave up */
            done = 1;
            
            if (!err && out_new_password) {
                err = kim_string_copy (out_new_password, new_password);
            }
            
            if (!err) {
                kim_error terr = KIM_NO_ERROR;
                kim_string saved_password = NULL;
                
                terr = kim_os_identity_get_saved_password (in_identity, 
                                                           &saved_password);
                if (!terr) { 
                    /* We changed the password and the user had their
                     * old password saved.  Update it. */
                    terr = kim_os_identity_set_saved_password (in_identity,
                                                               new_password);
                }
                
                kim_string_free (&saved_password);
            }

            if (err == KIM_DUPLICATE_UI_REQUEST_ERR) { err = KIM_NO_ERROR; }
        }
        
        kim_string_free (&rejected_message);
        kim_string_free (&rejected_description);
        
        kim_ui_free_string (in_ui_context, &old_password);
        kim_ui_free_string (in_ui_context, &new_password);
        kim_ui_free_string (in_ui_context, &verify_password);         
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_identity_change_password (kim_identity in_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_ui_context context;
    kim_boolean ui_inited = 0;

    if (!err && !in_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_ui_init (&context);
        if (!err) { ui_inited = 1; }
    }
    
    if (!err) {
        err = kim_identity_change_password_common (in_identity, 0, 
                                                   &context, NULL);
    }
    
    if (ui_inited) {
        kim_error fini_err = kim_ui_fini (&context);
        if (!err) { err = check_error (fini_err); }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_identity_free (kim_identity *io_identity)
{
    if (io_identity && *io_identity) { 
        kim_identity identity = *io_identity;
        
        if (identity->context) { 
            if (identity->principal) { 
                krb5_free_principal (identity->context, identity->principal); 
            }
            krb5_free_context (identity->context);
        }
        
        free (identity);
        *io_identity = NULL;
    }
}

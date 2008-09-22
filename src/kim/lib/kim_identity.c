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

#include <krb5.h>
#include <gssapi/gssapi.h>
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
    kim_error err = KIM_NO_ERROR;
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
    krb5_principal_data principal_data;  /* allocated by KIM so can't be returned */
    
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
        kim_count component_count = 1;
        
        va_start (args, in_1st_component);
        while (va_arg (args, kim_string)) { component_count++; }
        va_end (args);
        
        principal_data.length = component_count;
        principal_data.data = (krb5_data *) malloc (component_count * sizeof (krb5_data));
        if (!principal_data.data) { err = KIM_OUT_OF_MEMORY_ERR; }
    }   
    
    if (!err) {
        va_list args;
        krb5_int32 i;
        
        krb5_princ_set_realm_length (context, &principal_data, strlen (in_realm));
        krb5_princ_set_realm_data (context, &principal_data, (char *) in_realm);
        
        va_start (args, in_1st_component);
        for (i = 0; !err && (i < principal_data.length); i++) {
            kim_string component = NULL;
            if (i == 0) {
                err = kim_string_copy (&component, in_1st_component);
            } else {
                err = kim_string_copy (&component, va_arg (args, kim_string));
            }
            
            if (!err) {
                principal_data.data[i].data = (char *) component;
                principal_data.data[i].length = strlen (component);
            }
        }            
        va_end (args);
    }
    
    if (!err) {
        /* make a copy that has actually been allocated by the krb5 
         * library so krb5_free_principal can be called on it */
        err = krb5_error (identity->context,
                          krb5_copy_principal (identity->context, 
                                               &principal_data, 
                                               &identity->principal));
    }    
    
    if (!err) {
        *out_identity = identity;
        identity = NULL;
    }
    
    if (principal_data.data) { 
        krb5_int32 i;
        
        for (i = 0; i < principal_data.length; i++) {
            kim_string component = principal_data.data[i].data;
            kim_string_free (&component);
        }
        free (principal_data.data); 
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
    if (!err && !in_krb5_context  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_allocate (&identity);
    }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&identity->context));
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

kim_error kim_identity_get_components (kim_identity  in_identity,
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
        
        err = kim_identity_get_component_at_index (in_identity, 0, &component);
        
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
        err = krb5_error (in_identity->context,
                          krb5_copy_principal (in_identity->context, 
                                               in_identity->principal, 
                                               out_krb5_principal));
    }    
    
    return check_error (err);
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

kim_error kim_identity_change_password (kim_identity in_identity)
{
    kim_error err = KIM_NO_ERROR;
    kim_ui_context context;
    kim_boolean ui_inited = 0;
    kim_boolean done = 0;
    
    if (!err && !in_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_ui_init (&context);
        if (!err) { ui_inited = 1; }
    }
    
    while (!err && !done) {
        char *old_password = NULL;
        char *new_password = NULL;
        char *verify_password = NULL;
        kim_error rejected_err = KIM_NO_ERROR;
        kim_string rejected_message = NULL;
        kim_string rejected_description = NULL;
        
        err = kim_ui_change_password (&context,
                                      in_identity,
                                      0 /* old password not expired */,
                                      &old_password,
                                      &new_password,
                                      &verify_password);
        
        if (!err) {
            kim_comparison comparison;
            
            err = kim_string_compare (new_password, verify_password, &comparison);
            if (!err && !kim_comparison_is_equal_to (comparison)) {
                err = check_error (KIM_PASSWORD_MISMATCH_ERR);
            }
        }
        
        if (!err) {
            kim_credential credential = NULL;
            
            if (context.type == kim_ui_type_cli && context.tcontext) {
                /* command line has already gotten the credentials for us */
                credential = (kim_credential) context.tcontext;
            } else {
                err = kim_credential_create_for_change_password (&credential,
                                                                 in_identity,
                                                                 old_password);
            }
            
            if (!err) {
                err = kim_credential_change_password (credential, 
                                                      in_identity,
                                                      new_password,
                                                      &rejected_err,
                                                      &rejected_message,
                                                      &rejected_description);
                
            }  
            
            kim_credential_free (&credential);
        }
        
        if (!err || err == KIM_USER_CANCELED_ERR) {
            /* password change succeeded or the user gave up */
            done = 1;
            
        } else if (!err && rejected_err) {
            /* Password rejected, report it to the user */
            err = kim_ui_handle_error (&context, in_identity,
                                       rejected_err,
                                       rejected_message, 
                                       rejected_description);
            
        } else {
            /* Password change failed, report error to user */
            err = kim_ui_handle_kim_error (&context, in_identity, 
                                           kim_ui_error_type_change_password,
                                           err);                                        
        }
        
        kim_string_free (&rejected_message);
        kim_string_free (&rejected_description);
        kim_ui_free_string (&context, &old_password);
        kim_ui_free_string (&context, &new_password);
        kim_ui_free_string (&context, &verify_password);         
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

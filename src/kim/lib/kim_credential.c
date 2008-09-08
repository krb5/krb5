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
#include "kim_private.h"

struct kim_credential_iterator_opaque {
    krb5_context context;
    krb5_ccache ccache;
    krb5_cc_cursor cursor;
};

struct kim_credential_iterator_opaque kim_credential_iterator_initializer = { NULL, NULL, NULL };

/* ------------------------------------------------------------------------ */

kim_error kim_credential_iterator_create (kim_credential_iterator *out_credential_iterator,
                                          kim_ccache               in_ccache)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential_iterator credential_iterator = NULL;
    
    if (!err && !out_credential_iterator) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_ccache              ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        credential_iterator = malloc (sizeof (*credential_iterator));
        if (credential_iterator) { 
            *credential_iterator = kim_credential_iterator_initializer;
        } else {
            err = KIM_OUT_OF_MEMORY_ERR; 
        }
    }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&credential_iterator->context));
    }
    
    if (!err) {
        err = kim_ccache_get_krb5_ccache (in_ccache,
                                          credential_iterator->context,
                                          &credential_iterator->ccache);
    }
    
    if (!err) {
        err = krb5_error (credential_iterator->context,
                          krb5_cc_start_seq_get (credential_iterator->context, 
                                                 credential_iterator->ccache,
                                                 &credential_iterator->cursor));
    }
    
    if (!err) {
        *out_credential_iterator = credential_iterator;
        credential_iterator = NULL;
    }
    
    kim_credential_iterator_free (&credential_iterator);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_iterator_next (kim_credential_iterator  in_credential_iterator,
                                        kim_credential          *out_credential)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_credential_iterator) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_credential        ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        krb5_creds creds;
        
        krb5_error_code terr = krb5_cc_next_cred (in_credential_iterator->context, 
                                                  in_credential_iterator->ccache,
                                                  &in_credential_iterator->cursor,
                                                  &creds);
        
        if (!terr) {
            err = kim_credential_create_from_krb5_creds (out_credential,
                                                         in_credential_iterator->context,
                                                         &creds);
            
            krb5_free_cred_contents (in_credential_iterator->context, &creds);
            
        } else if (terr == KRB5_CC_END) {
            *out_credential = NULL; /* no more ccaches */
            
        } else {
            err = krb5_error (in_credential_iterator->context, terr);
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_credential_iterator_free (kim_credential_iterator *io_credential_iterator)
{
    if (io_credential_iterator && *io_credential_iterator) {
        if ((*io_credential_iterator)->context) { 
            if ((*io_credential_iterator)->ccache) {
                if ((*io_credential_iterator)->cursor) {
                    krb5_cc_end_seq_get ((*io_credential_iterator)->context, 
                                         (*io_credential_iterator)->ccache,
                                         &(*io_credential_iterator)->cursor);
                }
                krb5_cc_close ((*io_credential_iterator)->context, 
                               (*io_credential_iterator)->ccache);
            }
            krb5_free_context ((*io_credential_iterator)->context); 
        }
        free (*io_credential_iterator);
        *io_credential_iterator = NULL;
    }
}

#pragma mark -

/* ------------------------------------------------------------------------ */

struct kim_credential_opaque {
    krb5_context context;
    krb5_creds *creds;
};

struct kim_credential_opaque kim_credential_initializer = { NULL, NULL };

/* ------------------------------------------------------------------------ */

static inline kim_error kim_credential_allocate (kim_credential *out_credential)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    
    if (!err && !out_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        credential = malloc (sizeof (*credential));
        if (!credential) { err = KIM_OUT_OF_MEMORY_ERR; }
    }
    
    if (!err) {
        *credential = kim_credential_initializer;
        *out_credential = credential;
        credential = NULL;
    }
    
    kim_credential_free (&credential);
    
    return check_error (err);    
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_create_new (kim_credential *out_credential,
                                     kim_identity    in_client_identity,
                                     kim_options     in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    
    if (!err && !out_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_credential_allocate (&credential);
    }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&credential->context));
    }
    
    if (!err) {
#warning Get tickets here
    }
    
    if (!err) {
        *out_credential = credential;
        credential = NULL;
    }
    
    kim_credential_free (&credential);
    
    return check_error (err);
}

#ifndef LEAN_CLIENT

/* ------------------------------------------------------------------------ */

kim_error kim_credential_create_from_keytab (kim_credential *out_credential,
                                             kim_identity    in_identity,
                                             kim_options     in_options,
                                             kim_string      in_keytab)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    krb5_keytab keytab = NULL;
    krb5_creds creds;
    kim_boolean free_creds = FALSE;
    krb5_principal principal = NULL;
    kim_time start_time = 0;
    kim_string service_name = NULL;
    krb5_get_init_creds_opt *init_cred_options = NULL;
    
    if (!err && !out_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_credential_allocate (&credential);
    }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&credential->context));
    }
    
    if (!err) {
        kim_options options = in_options;
        
        if (!options) {
            err = kim_options_create (&options);
        }
	
	if (!err) {
	    err = kim_options_get_start_time (options, &start_time);
	}
        
	if (!err) {
	    err = kim_options_get_service_name (options, &service_name);
	}
	
        if (!err) {
            err = kim_options_get_init_cred_options (options, 
                                                     credential->context,
                                                     &init_cred_options);
        }
        
        if (options != in_options) { kim_options_free (&options); }
    }
    
    if (!err) {
        if (in_keytab) {
            err = krb5_error (credential->context,
                              krb5_kt_resolve (credential->context, 
                                               in_keytab, &keytab));
        } else {
            err = krb5_error (credential->context,
                              krb5_kt_default (credential->context, &keytab));
        }
    }
    
    if (!err) {
        if (in_identity) {
            err = kim_identity_get_krb5_principal (in_identity, 
                                                   credential->context, 
                                                   &principal);
        } else {
            krb5_kt_cursor cursor = NULL;
            krb5_keytab_entry entry;
            kim_boolean entry_allocated = FALSE;
            
            err = krb5_error (credential->context,
                              krb5_kt_start_seq_get (credential->context, 
                                                     keytab, 
                                                     &cursor));
            
            if (!err) {
                err = krb5_error (credential->context,
                                  krb5_kt_next_entry (credential->context, 
                                                      keytab, 
                                                      &entry, 
                                                      &cursor));
                entry_allocated = (err == KIM_NO_ERROR); /* remember to free later */
            }
            
            if (!err) {
                err = krb5_error (credential->context,
                                  krb5_copy_principal (credential->context, 
                                                       entry.principal, 
                                                       &principal));
            }
            
            if (entry_allocated) { krb5_free_keytab_entry_contents (credential->context, &entry); }
            if (cursor         ) { krb5_kt_end_seq_get (credential->context, keytab, &cursor); }
        }
    }
    
    if (!err) {
        err = krb5_error (credential->context,
                          krb5_get_init_creds_keytab (credential->context, 
                                                      &creds, 
                                                      principal, 
                                                      keytab, 
                                                      start_time, 
                                                      (char *) service_name, 
                                                      init_cred_options));
        if (!err) { free_creds = TRUE; }
    }
    
    if (!err) {
        err = krb5_error (credential->context,
                          krb5_copy_creds (credential->context,
                                           &creds, 
                                           &credential->creds));
    }
    
    if (!err) {
        *out_credential = credential;
        credential = NULL;
    }
    
    if (principal ) { krb5_free_principal (credential->context, principal); }
    if (free_creds) { krb5_free_cred_contents (credential->context, &creds); }
    kim_options_free_init_cred_options (credential->context, &init_cred_options);
    kim_string_free (&service_name);
    kim_credential_free (&credential);
    
    return check_error (err);
}

#endif /* LEAN_CLIENT */

/* ------------------------------------------------------------------------ */

kim_error kim_credential_create_from_krb5_creds (kim_credential *out_credential,
                                                 krb5_context    in_krb5_context,
                                                 krb5_creds     *in_krb5_creds)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    
    if (!err && !out_credential ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_krb5_creds  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_krb5_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_credential_allocate (&credential);
    }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&credential->context));
    }
    
    if (!err) {
        err = krb5_error (credential->context,
                          krb5_copy_creds (credential->context, 
                                           in_krb5_creds, 
                                           &credential->creds));
    }
    
    if (!err) {
        *out_credential = credential;
        credential = NULL;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_copy (kim_credential *out_credential,
                               kim_credential  in_credential)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    
    if (!err && !out_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_credential ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_credential_allocate (&credential);
    }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&credential->context));
    }
    
    if (!err) {
        err = krb5_error (credential->context,
                          krb5_copy_creds (credential->context, 
                                           in_credential->creds, 
                                           &credential->creds));
    }
    
    if (!err) {
        *out_credential = credential;
        credential = NULL;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_krb5_creds (kim_credential   in_credential,
                                         krb5_context     in_krb5_context,
                                         krb5_creds     **out_krb5_creds)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_credential  ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_krb5_context) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_krb5_creds ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = krb5_error (in_krb5_context,
                          krb5_copy_creds (in_krb5_context, 
                                           in_credential->creds, 
                                           out_krb5_creds));
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_client_identity (kim_credential  in_credential,
                                              kim_identity   *out_client_identity)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_credential      ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_client_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_create_from_krb5_principal (out_client_identity,
                                                       in_credential->context,
                                                       in_credential->creds->client);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_service_identity (kim_credential  in_credential,
                                               kim_identity   *out_service_identity)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_credential       ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_service_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_identity_create_from_krb5_principal (out_service_identity,
                                                       in_credential->context,
                                                       in_credential->creds->server);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_is_tgt (kim_credential  in_credential,
                                 kim_boolean     *out_is_tgt)
{
    kim_error err = KIM_NO_ERROR;
    kim_identity service = NULL;
    
    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_is_tgt   ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_credential_get_service_identity (in_credential, &service);
    }
    
    if (!err) {
        err = kim_identity_is_tgt_service (service, out_is_tgt);
    }
    
    kim_identity_free (&service);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_state (kim_credential           in_credential,
                                    kim_credential_state    *out_state)
{
    kim_error err = KIM_NO_ERROR;
    kim_time expiration_time = 0;
    kim_time start_time = 0;
    krb5_timestamp now = 0;
    
    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !out_state    ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = kim_credential_get_expiration_time (in_credential, &expiration_time);
    }
    
    if (!err) {
        err = kim_credential_get_start_time (in_credential, &start_time);
    }
    
    if (!err) {
        krb5_int32 usec;
        
        err = krb5_error (in_credential->context,
                          krb5_us_timeofday (in_credential->context, 
                                             &now, &usec));
    }
    
    if (!err) {
        *out_state = kim_credentials_state_valid;
        
        if (expiration_time <= now) {
            *out_state = kim_credentials_state_expired;
            
        } else if ((in_credential->creds->ticket_flags & TKT_FLG_POSTDATED) && 
                   (in_credential->creds->ticket_flags & TKT_FLG_INVALID)) {
            if (start_time > now) { 
                *out_state = kim_credentials_state_not_yet_valid;
            } else {
                *out_state = kim_credentials_state_needs_validation;
            }
            
        } else if (in_credential->creds->addresses) { /* ticket contains addresses */
            krb5_address **laddresses = NULL;
            
            krb5_error_code code = krb5_os_localaddr (in_credential->context, 
                                                      &laddresses);
            if (!code) { laddresses = NULL; }
            
            if (laddresses) { /* assume valid if the local host has no addresses */
                kim_boolean found_match = FALSE;
                kim_count i = 0;
                
                for (i = 0; in_credential->creds->addresses[i]; i++) {
                    if (!krb5_address_search (in_credential->context, 
                                              in_credential->creds->addresses[i], 
                                              laddresses)) {
                        found_match = TRUE;
                        break;
                    }
                }
                
                if (!found_match) {
                    *out_state = kim_credentials_state_address_mismatch;
                }
            }
            
            if (laddresses) { krb5_free_addresses (in_credential->context, 
                                                   laddresses); }
        }
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_start_time (kim_credential  in_credential,
                                         kim_time       *out_start_time)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_start_time = (in_credential->creds->times.starttime ? 
                           in_credential->creds->times.starttime :
                           in_credential->creds->times.authtime);
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_expiration_time (kim_credential  in_credential,
                                              kim_time       *out_expiration_time)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_expiration_time = in_credential->creds->times.endtime;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_get_renewal_expiration_time (kim_credential  in_credential,
                                                      kim_time       *out_renewal_expiration_time)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        *out_renewal_expiration_time = in_credential->creds->times.renew_till;
    }
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_store (kim_credential  in_credential,
                                kim_identity    in_client_identity,
                                kim_ccache     *out_ccache)
{
    kim_error err = KIM_NO_ERROR;
    krb5_context context = NULL;
    krb5_ccache k5ccache = NULL;
    kim_string type = NULL;
    krb5_principal client_principal = NULL;
    kim_boolean destroy_ccache_on_error = FALSE;
    
    if (!err && !in_credential     ) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    if (!err && !in_client_identity) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        err = krb5_error (NULL, krb5_init_context (&context));
    }
    
    if (!err) {
        err = kim_identity_get_krb5_principal (in_client_identity, context, 
                                               &client_principal);
    }
    
    if (!err) {
        char *environment_ccache = getenv ("KRB5CCNAME");
        
        if (environment_ccache) {
            err = krb5_error (context,
                              krb5_cc_resolve (context, environment_ccache, 
                                               &k5ccache));
            
        } else {
            kim_ccache ccache = NULL;
            
            err = kim_ccache_create_from_client_identity (&ccache, 
                                                          in_client_identity);
            
            if (!err) {
                err = kim_ccache_get_krb5_ccache (ccache, context, &k5ccache);
                
            } else if (err == KIM_NO_SUCH_PRINCIPAL_ERR) {
                /* Nothing to replace, create a new ccache */
                err = krb5_error (context,
                                  krb5_cc_new_unique (context, "API", NULL, 
                                                      &k5ccache));
                if (!err) { destroy_ccache_on_error = TRUE; }
            }
            
            kim_ccache_free (&ccache);
        }
    }
    
    if (!err) {
	err = krb5_error (in_credential->context,
                          krb5_cc_initialize (in_credential->context, 
                                              k5ccache, client_principal));
    }
    
    if (!err) {
	err = krb5_error (in_credential->context,
                          krb5_cc_store_cred (in_credential->context, 
                                              k5ccache, in_credential->creds));
    }
    
#warning Call plugins here
    
    if (!err && out_ccache) {
        err = kim_ccache_create_from_krb5_ccache (out_ccache, context, k5ccache);
    }
    
    if (k5ccache) { 
        if (err && destroy_ccache_on_error) {
            krb5_cc_destroy (in_credential->context, k5ccache); 
        } else {
            krb5_cc_close (in_credential->context, k5ccache); 
        }
    }
    if (client_principal) { krb5_free_principal (context, client_principal); }
    if (context         ) { krb5_free_context (context); }
    kim_string_free (&type);
    
    return check_error (err);
}

#ifndef LEAN_CLIENT

/* ------------------------------------------------------------------------ */

kim_error kim_credential_verify (kim_credential in_credential,
                                 kim_identity   in_service_identity,
                                 kim_string     in_keytab,
                                 kim_boolean    in_fail_if_no_service_key)
{
    kim_error err = KIM_NO_ERROR;
    krb5_context scontext = NULL;
    krb5_principal service_principal = NULL;
    krb5_keytab keytab = NULL;
    
    if (!err && !in_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
	err = krb5_error (NULL, krb5_init_secure_context (&scontext));
    }
    
    if (!err && in_service_identity) {
	err = kim_identity_get_krb5_principal (in_service_identity, scontext, &service_principal);
    }
    
    if (in_keytab) {
	err = krb5_error (scontext, 
                          krb5_kt_resolve (scontext, in_keytab, &keytab));
    }
    
    if (!err) {
	krb5_verify_init_creds_opt options;
        
	/* That's "no key == fail" not "no fail" >.< */
        krb5_verify_init_creds_opt_init (&options);
        krb5_verify_init_creds_opt_set_ap_req_nofail (&options, in_fail_if_no_service_key);
        
	err = krb5_error (scontext,
                          krb5_verify_init_creds (scontext, in_credential->creds, 
						  service_principal,
						  keytab,
						  NULL /* don't store creds in ccache */,
						  &options));
	
	if (err && !service_principal && in_fail_if_no_service_key) {
	    /* If the service principal wasn't specified but we are supposed to
             * fail without a key we should walk the keytab trying to find one 
             * that succeeds. */
            krb5_error_code terr = 0;
            kim_boolean verified = 0;
	    krb5_kt_cursor cursor = NULL;
	    krb5_keytab_entry entry;
            
	    
	    if (!keytab) {
                terr = krb5_kt_default (scontext, &keytab);
	    }
	    
	    if (!terr) {
		terr = krb5_kt_start_seq_get (scontext, keytab, &cursor);
	    }
	    
	    while (!terr && !verified) {
                kim_boolean free_entry = 0;
                
		terr = krb5_kt_next_entry (scontext, keytab, &entry, &cursor);
		free_entry = !terr; /* remember to free */
                
                if (!terr) {
                    terr = krb5_verify_init_creds (scontext, in_credential->creds,
                                                   entry.principal /* get principal for the 1st entry */, 
                                                   keytab,
                                                   NULL /* don't store creds in ccache */,
                                                   &options);
                }
                
                if (!terr) {
                    verified = 1;
                }
                
                if (free_entry) { krb5_free_keytab_entry_contents (scontext, &entry); }
	    }
            
            if (!terr && verified) {
                /* We found a key that verified! */
                err = KIM_NO_ERROR;
            }
            
	    if (cursor) { krb5_kt_end_seq_get (scontext, keytab, &cursor); }
	}
    }
    
    if (keytab           ) { krb5_kt_close (scontext, keytab); }
    if (service_principal) { krb5_free_principal (scontext, service_principal); }
    if (scontext         ) { krb5_free_context (scontext); }
    
    return check_error (err);
}

#endif /* LEAN_CLIENT */

/* ------------------------------------------------------------------------ */

kim_error kim_credential_renew (kim_credential *io_credential,
                                kim_options     in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_string service_name = NULL;
    krb5_ccache ccache = NULL;
    
    if (!err && !io_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_options options = in_options;
	
        if (!options) {
            err = kim_options_create (&options);
        }
        
	if (!err) {
	    err = kim_options_get_service_name (options, &service_name);
	}
        
        if (options != in_options) { kim_options_free (&options); }
    }
    
    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_new_unique ((*io_credential)->context, 
					      "MEMORY", NULL, 
					      &ccache));
    }
    
    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_initialize ((*io_credential)->context, ccache, 
					      (*io_credential)->creds->client));
    }
    
    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_store_cred ((*io_credential)->context, ccache, 
					      (*io_credential)->creds));
    }
    
    if (!err) {
	krb5_creds creds;
	krb5_creds *renewed_creds = NULL;
	kim_boolean free_creds = 0;
	
	err = krb5_error ((*io_credential)->context,
                          krb5_get_renewed_creds ((*io_credential)->context, 
						  &creds, (*io_credential)->creds->client,
						  ccache, (char *) service_name));
	if (!err) { free_creds = 1; }
        
	if (!err) {
	    err = krb5_error ((*io_credential)->context,
                              krb5_copy_creds ((*io_credential)->context, 
                                               &creds, &renewed_creds));
	}
	
	if (!err) {
	    /* replace the credentials */
	    krb5_free_creds ((*io_credential)->context, (*io_credential)->creds);	    
	    (*io_credential)->creds = renewed_creds;
	}
	
	if (free_creds) { krb5_free_cred_contents ((*io_credential)->context, &creds); }
    }
    
    if (ccache) { krb5_cc_destroy ((*io_credential)->context, ccache); }
    kim_string_free (&service_name);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

kim_error kim_credential_validate (kim_credential *io_credential,
                                   kim_options     in_options)
{
    kim_error err = KIM_NO_ERROR;
    kim_string service_name = NULL;
    krb5_ccache ccache = NULL;
    
    if (!err && !io_credential) { err = check_error (KIM_NULL_PARAMETER_ERR); }
    
    if (!err) {
        kim_options options = in_options;
	
        if (!options) {
            err = kim_options_create (&options);
        }
	
	if (!err) {
	    err = kim_options_get_service_name (options, &service_name);
	}
        
        if (options != in_options) { kim_options_free (&options); }
    }
    
    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_new_unique ((*io_credential)->context, 
					      "MEMORY", NULL, 
					      &ccache));
    }
    
    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_initialize ((*io_credential)->context, ccache, 
					      (*io_credential)->creds->client));
    }
    
    if (!err) {
	err = krb5_error ((*io_credential)->context,
                          krb5_cc_store_cred ((*io_credential)->context, ccache, 
					      (*io_credential)->creds));
    }
    
    if (!err) {
	krb5_creds creds;
	krb5_creds *validated_creds = NULL;
	kim_boolean free_creds = 0;
	
        err = krb5_error ((*io_credential)->context,
                          krb5_get_validated_creds ((*io_credential)->context, 
						    &creds, 
                                                    (*io_credential)->creds->client, 
						    ccache, 
                                                    (char *) service_name));
	if (!err) { free_creds = 1; }
	
	if (!err) {
	    err = krb5_error ((*io_credential)->context,
                              krb5_copy_creds ((*io_credential)->context, 
                                               &creds, &validated_creds));
	}
	
	if (!err) {
	    /* replace the credentials */
	    krb5_free_creds ((*io_credential)->context, (*io_credential)->creds);	    
	    (*io_credential)->creds = validated_creds;
	}
	
	if (free_creds) { krb5_free_cred_contents ((*io_credential)->context, &creds); }
    }
    
    if (ccache) { krb5_cc_destroy ((*io_credential)->context, ccache); }
    kim_string_free (&service_name);
    
    return check_error (err);
}

/* ------------------------------------------------------------------------ */

void kim_credential_free (kim_credential *io_credential)
{
    if (io_credential && *io_credential) {
        if ((*io_credential)->context) {
            if ((*io_credential)->creds) {
                krb5_free_creds ((*io_credential)->context, (*io_credential)->creds);
            }
            krb5_free_context ((*io_credential)->context);
        }
        free (*io_credential);
        *io_credential = NULL;
    }
}

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

#ifdef KIM_TO_KLL_SHIM

#include "CredentialsCache.h"
#include "KerberosLogin.h"
#include "KerberosLoginPrivate.h"
#include <kim/kim.h>
#include "kim_private.h"
#include "k5-thread.h"
#include <time.h>

/* 
 * Deprecated Error codes 
 */
enum {
    /* Carbon Dialog errors */
    klDialogDoesNotExistErr             = 19676,
    klDialogAlreadyExistsErr,
    klNotInForegroundErr,
    klNoAppearanceErr,
    klFatalDialogErr,
    klCarbonUnavailableErr    
};

krb5_get_init_creds_opt *__KLLoginOptionsGetKerberos5Options (KLLoginOptions ioOptions);
KLTime __KLLoginOptionsGetStartTime (KLLoginOptions ioOptions);
char *__KLLoginOptionsGetServiceName (KLLoginOptions ioOptions);


/* ------------------------------------------------------------------------ */

static KLStatus kl_check_error_ (kim_error inError, const char *function, const char *file, int line)
{
    kim_error err = inError;
    
    switch (err) {
        case ccNoError:
            err = klNoErr;
            break;
            
        case ccErrBadName:
            err = klPrincipalDoesNotExistErr;
            break;
            
        case ccErrCCacheNotFound:
            err = klCacheDoesNotExistErr;
            break;
            
        case ccErrCredentialsNotFound:
            err = klNoCredentialsErr;
            break;
            
        case KIM_OUT_OF_MEMORY_ERR:
        case ccErrNoMem:
            err = klMemFullErr;
            break;
            
        case ccErrBadCredentialsVersion:
            err = klInvalidVersionErr;
            break;
            
        case KIM_NULL_PARAMETER_ERR:
        case ccErrBadParam:
        case ccIteratorEnd:
        case ccErrInvalidContext:
        case ccErrInvalidCCache:
        case ccErrInvalidString:
        case ccErrInvalidCredentials:
        case ccErrInvalidCCacheIterator:
        case ccErrInvalidCredentialsIterator:
        case ccErrInvalidLock:
        case ccErrBadAPIVersion:
        case ccErrContextLocked:
        case ccErrContextUnlocked:
        case ccErrCCacheLocked:
        case ccErrCCacheUnlocked:
        case ccErrBadLockType:
        case ccErrNeverDefault:
            err = klParameterErr;
            break;
            
        case KIM_USER_CANCELED_ERR:
        case KRB5_LIBOS_PWDINTR:
            err = klUserCanceledErr;
            break;
    }
    
    if (err) {
        kim_debug_printf ("%s() remapped %d to %d ('%s') at %s: %d", 
                          function, inError, err, kim_error_message (err), 
                          file, line);
    }
    
    return err;
}
#define kl_check_error(err) kl_check_error_(err, __FUNCTION__, __FILE__, __LINE__)

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireTickets (KLPrincipal   inPrincipal,
                           KLPrincipal  *outPrincipal,
                           char        **outCredCacheName)
{
    return kl_check_error (KLAcquireInitialTickets (inPrincipal, 
                                                    NULL, 
                                                    outPrincipal, 
                                                    outCredCacheName));
}

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireNewTickets (KLPrincipal  inPrincipal,
                              KLPrincipal  *outPrincipal,
                              char        **outCredCacheName)
{
    return kl_check_error (KLAcquireNewInitialTickets (inPrincipal, 
                                                       NULL, 
                                                       outPrincipal, 
                                                       outCredCacheName));
}

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireTicketsWithPassword (KLPrincipal      inPrincipal,
                                       KLLoginOptions   inLoginOptions,
                                       const char      *inPassword,
                                       char           **outCredCacheName)
{
    return kl_check_error (KLAcquireInitialTicketsWithPassword (inPrincipal, 
                                                                inLoginOptions, 
                                                                inPassword, 
                                                                outCredCacheName));
}

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireNewTicketsWithPassword (KLPrincipal      inPrincipal,
                                          KLLoginOptions   inLoginOptions,
                                          const char      *inPassword,
                                          char           **outCredCacheName)
{
    return kl_check_error (KLAcquireNewInitialTicketsWithPassword (inPrincipal, 
                                                                   inLoginOptions, 
                                                                   inPassword, 
                                                                   outCredCacheName));
}

/* ------------------------------------------------------------------------ */

KLStatus KLSetApplicationOptions (const void *inAppOptions)
{
    /* Deprecated */
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

KLStatus KLGetApplicationOptions (void *outAppOptions)
{
    /* Deprecated -- this function took a struct declared on the caller's
     * stack.  It used to fill in the struct with information about the
     * Mac OS 9 dialog used for automatic prompting.  Since there is no
     * way for us provide valid values, just leave the struct untouched
     * and return a reasonable error. */
    return kl_check_error (klDialogDoesNotExistErr);
}

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireInitialTickets (KLPrincipal      inPrincipal,
                                  KLLoginOptions   inLoginOptions,
                                  KLPrincipal     *outPrincipal,
                                  char           **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    kim_string name = NULL;
    kim_identity identity = NULL;
    
    if (!err) {
        err = kim_ccache_create_new_if_needed (&ccache, 
                                               inPrincipal,
                                               inLoginOptions);
    }
    
    if (!err && outPrincipal) {
        err = kim_ccache_get_client_identity (ccache, &identity);
    }
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, &name);
    }
    
    if (!err) {
        if (outPrincipal) {
            *outPrincipal = identity;
            identity = NULL;
        }
        if (outCredCacheName) {
            *outCredCacheName = (char *) name;
            name = NULL;
        }
    }
    
    kim_string_free (&name);
    kim_identity_free (&identity);    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireNewInitialTickets (KLPrincipal      inPrincipal,
                                     KLLoginOptions   inLoginOptions,
                                     KLPrincipal     *outPrincipal,
                                     char           **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    kim_string name = NULL;
    kim_identity identity = NULL;
    
    err = kim_ccache_create_new (&ccache, inPrincipal, inLoginOptions);
    
    if (!err && outPrincipal) {
        err = kim_ccache_get_client_identity (ccache, &identity);
    }
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, &name);
    }
    
    if (!err) {
        if (outPrincipal) {
            *outPrincipal = identity;
            identity = NULL;
        }
        if (outCredCacheName) {
            *outCredCacheName = (char *) name;
            name = NULL;
        }
    }
    
    kim_string_free (&name);
    kim_identity_free (&identity);    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLDestroyTickets (KLPrincipal inPrincipal)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    
    if (!err) {
        err = kim_ccache_create_from_client_identity (&ccache, inPrincipal);
    }
    
    if (!err) {
        err = kim_ccache_destroy (&ccache);
    }
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLChangePassword (KLPrincipal inPrincipal)
{
    return kl_check_error (kim_identity_change_password (inPrincipal));
}

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireInitialTicketsWithPassword (KLPrincipal      inPrincipal,
                                              KLLoginOptions   inLoginOptions,
                                              const char      *inPassword,
                                              char           **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    
    if (!err) {
        err = kim_ccache_create_new_if_needed_with_password (&ccache, 
                                                             inPrincipal,
                                                             inLoginOptions,
                                                             inPassword);
    }
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, 
                                           (kim_string *) outCredCacheName);
    }    
    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireNewInitialTicketsWithPassword (KLPrincipal      inPrincipal,
                                                 KLLoginOptions   inLoginOptions,
                                                 const char      *inPassword,
                                                 char           **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    
    err = kim_ccache_create_new_with_password (&ccache, 
                                               inPrincipal, 
                                               inLoginOptions,
                                               inPassword);
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, 
                                           (kim_string *) outCredCacheName);
    }    
    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireNewInitialTicketCredentialsWithPassword (KLPrincipal      inPrincipal,
                                                           KLLoginOptions   inLoginOptions,
                                                           const char      *inPassword,
                                                           krb5_context     inV5Context,
                                                           KLBoolean       *outGotV4Credentials,
                                                           KLBoolean       *outGotV5Credentials,
                                                           void            *outV4Credentials,
                                                           krb5_creds      *outV5Credentials)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    krb5_creds *creds = NULL;
    
    if (!err) {
        err = kim_credential_create_new_with_password (&credential,
                                                       inPrincipal,
                                                       inLoginOptions,
                                                       inPassword);
    }
    
    if (!err) {
        err = kim_credential_get_krb5_creds (credential, 
                                             inV5Context,
                                             &creds);
    }
    
    if (!err) {
        *outGotV5Credentials = 1;
        *outGotV4Credentials = 0;
        *outV5Credentials = *creds;
        free (creds); /* eeeew */
        creds = NULL;
    }
    
    kim_credential_free (&credential);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLStoreNewInitialTicketCredentials (KLPrincipal     inPrincipal,
                                             krb5_context    inV5Context,
                                             void           *inV4Credentials,
                                             krb5_creds     *inV5Credentials,
                                             char          **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    kim_ccache ccache = NULL;
    
    err = kim_credential_create_from_krb5_creds (&credential,
                                                 inV5Context, 
                                                 inV5Credentials);
    
    if (!err) {
        err = kim_credential_store (credential, inPrincipal, &ccache);
    }
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, 
                                           (kim_string *) outCredCacheName);
    }    
    
    kim_ccache_free (&ccache);
    kim_credential_free (&credential);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLVerifyInitialTickets (KLPrincipal   inPrincipal,
                                 KLBoolean     inFailIfNoHostKey,
                                 char        **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    
    err = kim_ccache_create_from_client_identity (&ccache, inPrincipal);
    
    if (!err) {
        err = kim_ccache_verify (ccache, 
                                 KIM_IDENTITY_ANY, 
                                 NULL, 
                                 inFailIfNoHostKey);
    }
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, 
                                           (kim_string *) outCredCacheName);
    }    
    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLVerifyInitialTicketCredentials (void        *inV4Credentials,
                                           krb5_creds  *inV5Credentials,
                                           KLBoolean    inFailIfNoHostKey)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    krb5_context context = NULL;
    
    err = krb5_error (NULL, krb5_init_context (&context));
    
    if (!err) {
        err = kim_credential_create_from_krb5_creds (&credential,
                                                     context, 
                                                     inV5Credentials);
    }
    
    if (!err) {
        err = kim_credential_verify (credential, KIM_IDENTITY_ANY, 
                                     NULL, inFailIfNoHostKey);
    }
    
    if (context) { krb5_free_context (context); }
    kim_credential_free (&credential);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLAcquireNewInitialTicketsWithKeytab (KLPrincipal      inPrincipal,
                                               KLLoginOptions   inLoginOptions,
                                               const char      *inKeytabName,
                                               char           **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    
    err = kim_ccache_create_from_keytab (&ccache, 
                                         inPrincipal, 
                                         inLoginOptions,
                                         inKeytabName);
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, 
                                           (kim_string *) outCredCacheName);
    }    
    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLRenewInitialTickets (KLPrincipal      inPrincipal,
                                KLLoginOptions   inLoginOptions,
                                KLPrincipal     *outPrincipal,
                                char           **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    kim_string name = NULL;
    kim_identity identity = NULL;
    
    err = kim_ccache_create_from_client_identity (&ccache, inPrincipal);
    
    if (!err) {
        err = kim_ccache_renew (ccache, inLoginOptions);
    }
    
    if (!err && outPrincipal) {
        err = kim_ccache_get_client_identity (ccache, &identity);
    }
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, &name);
    }
    
    if (!err) {
        if (outPrincipal) {
            *outPrincipal = identity;
            identity = NULL;
        }
        if (outCredCacheName) {
            *outCredCacheName = (char *) name;
            name = NULL;
        }
    }
    
    kim_string_free (&name);
    kim_identity_free (&identity);
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLValidateInitialTickets (KLPrincipal      inPrincipal,
                                   KLLoginOptions   inLoginOptions,
                                   char           **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    
    err = kim_ccache_create_from_client_identity (&ccache, inPrincipal);
    
    if (!err) {
        err = kim_ccache_validate (ccache, inLoginOptions);
    }
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, 
                                           (kim_string *) outCredCacheName);
    }    
    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

static cc_time_t g_cc_change_time = 0;
static KLTime g_kl_change_time = 0;
static k5_mutex_t g_change_time_mutex = K5_MUTEX_PARTIAL_INITIALIZER;

MAKE_INIT_FUNCTION(kim_change_time_init);
MAKE_FINI_FUNCTION(kim_change_time_fini);

/* ------------------------------------------------------------------------ */

static int kim_change_time_init (void)
{
    g_kl_change_time = time (NULL);
    
    return k5_mutex_finish_init(&g_change_time_mutex);
}

/* ------------------------------------------------------------------------ */

static void kim_change_time_fini (void)
{
    if (!INITIALIZER_RAN (kim_change_time_init) || PROGRAM_EXITING ()) {
	return;
    }
    
    k5_mutex_destroy(&g_change_time_mutex);
}

/* ------------------------------------------------------------------------ */

KLStatus KLLastChangedTime (KLTime *outLastChangedTime)
{
    KLStatus     err = CALL_INIT_FUNCTION (kim_change_time_init);
    kim_error mutex_err = KIM_NO_ERROR;
    cc_context_t context = NULL;
    cc_time_t    ccChangeTime = 0;
    
    if (!err && !outLastChangedTime) { err = kl_check_error (klParameterErr); }
        
    if (!err) {
        mutex_err = k5_mutex_lock (&g_change_time_mutex);
        if (mutex_err) { err = mutex_err; }
    }

    if (!err) {
        err = cc_initialize (&context, ccapi_version_4, NULL, NULL);
    }
    
    if (!err) {
        err = cc_context_get_change_time (context, &ccChangeTime);
    }
    
    if (!err) {
        /* cc_context_get_change_time returns 0 if there are no tickets
         * but KLLastChangedTime always returned the current time.  So
         * fake the current time if cc_context_get_change_time returns 0. */
        if (ccChangeTime > g_cc_change_time) {
            /* changed, make sure g_kl_change_time increases in value */
            if (ccChangeTime > g_kl_change_time) {
                g_kl_change_time = ccChangeTime;
            } else {
                g_kl_change_time++; /* we got ahead of the ccapi, just increment */
            }
            g_cc_change_time = ccChangeTime;
        }
        
        *outLastChangedTime = g_kl_change_time;
    }
    
    if (context   ) { cc_context_release (context); }
    if (!mutex_err) { k5_mutex_unlock (&g_change_time_mutex); }
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLCacheHasValidTickets (KLPrincipal         inPrincipal,
                                 KLKerberosVersion   inKerberosVersion,
                                 KLBoolean          *outFoundValidTickets,
                                 KLPrincipal        *outPrincipal,
                                 char              **outCredCacheName)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    kim_credential_state state = kim_credentials_state_valid;
    kim_identity identity = NULL;
    kim_string name = NULL;
    
    if (!outFoundValidTickets) { err = kl_check_error (klParameterErr); }
    
    if (!err) {
        err = kim_ccache_create_from_client_identity (&ccache, inPrincipal);
    }
    
    if (!err) {
        err = kim_ccache_get_state (ccache, &state);
    }
    
    if (!err && outPrincipal) {
        err = kim_ccache_get_client_identity (ccache, &identity);
        if (err) {
            err = KIM_NO_ERROR;
            identity = NULL;
        } 
    }
    
    if (!err && outCredCacheName) {
        err = kim_ccache_get_display_name (ccache, &name);
    }
    
    if (!err) {
        *outFoundValidTickets = (state == kim_credentials_state_valid);
        if (outPrincipal) {
            *outPrincipal = identity;
            identity = NULL;
        }
        if (outCredCacheName) {
            *outCredCacheName = (char *) name;
            name = NULL;
        }
    }
    
    kim_string_free (&name);
    kim_identity_free (&identity);
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLTicketStartTime (KLPrincipal        inPrincipal,
                            KLKerberosVersion  inKerberosVersion,
                            KLTime            *outStartTime)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    kim_time start_time = 0;
    
    if (!err) {
        err = kim_ccache_create_from_client_identity (&ccache, inPrincipal);
    }
    
    if (!err) {
        err = kim_ccache_get_start_time (ccache, &start_time);
    }
    
    if (!err) {
        *outStartTime = start_time;
    }
    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLTicketExpirationTime (KLPrincipal        inPrincipal,
                                 KLKerberosVersion  inKerberosVersion,
                                 KLTime            *outExpirationTime)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    kim_time expiration_time = 0;
    
    if (!err) {
        err = kim_ccache_create_from_client_identity (&ccache, inPrincipal);
    }
    
    if (!err) {
        err = kim_ccache_get_expiration_time (ccache, &expiration_time);
    }
    
    if (!err) {
        *outExpirationTime = expiration_time;
    }
    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLSetSystemDefaultCache (KLPrincipal inPrincipal)
{
    kim_error err = KIM_NO_ERROR;
    kim_ccache ccache = NULL;
    
    if (!err) {
        err = kim_ccache_create_from_client_identity (&ccache, inPrincipal);
    }
    
    if (!err) {
        err = kim_ccache_set_default (ccache);
    }
    
    kim_ccache_free (&ccache);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLHandleError (KLStatus           inError,
                        KLDialogIdentifier inDialogIdentifier,
                        KLBoolean          inShowAlert)
{
    kim_error err = KIM_NO_ERROR;
    kim_ui_context context;
    kim_boolean ui_inited = 0;
    
    if (!err) {
        err = kim_ui_init (&context);
        if (!err) { ui_inited = 1; }
    }
    
    if (!err) {
        int type = kim_ui_error_type_generic;
        
        switch (inDialogIdentifier) {
            case loginLibrary_LoginDialog:
                type = kim_ui_error_type_authentication;
                break;
            case loginLibrary_ChangePasswordDialog:
                type = kim_ui_error_type_change_password;
                break;
            default:
                type = kim_ui_error_type_generic;
                break;
        }
        
        err = kim_ui_handle_kim_error (&context, 
                                       KIM_IDENTITY_ANY, type, inError);
    }
    
    if (ui_inited) {
        kim_error fini_err = kim_ui_fini (&context);
        if (!err) { err = kl_check_error (fini_err); }
    }
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLGetErrorString (KLStatus   inError,
                           char     **outErrorString)
{
    return kl_check_error (kim_string_create_for_last_error ((kim_string *) outErrorString,
                                                             inError));
}

/* ------------------------------------------------------------------------ */

KLStatus KLCancelAllDialogs (void)
{
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

/* Kerberos change password dialog low level functions */

KLStatus KLChangePasswordWithPasswords (KLPrincipal   inPrincipal,
                                        const char   *inOldPassword,
                                        const char   *inNewPassword,
                                        KLBoolean    *outRejected,
                                        char        **outRejectionError,
                                        char        **outRejectionDescription)
{
    kim_error err = KIM_NO_ERROR;
    kim_credential credential = NULL;
    kim_ui_context context;
    kim_boolean ui_inited = 0;
    kim_error rejected_err = KIM_NO_ERROR;
    kim_string rejected_message = NULL;
    kim_string rejected_description = NULL;
    
    if (!inOldPassword) { err = kl_check_error (klParameterErr); }
    if (!inNewPassword) { err = kl_check_error (klParameterErr); }
    if (!outRejected  ) { err = kl_check_error (klParameterErr); }
    
    if (!err) {
        err = kim_ui_init (&context);
        if (!err) { ui_inited = 1; }
    }
    
    if (!err) {
        kim_boolean was_prompted = 0;
        
        err = kim_credential_create_for_change_password (&credential,
                                                         inPrincipal,
                                                         inOldPassword,
                                                         &context,
                                                         &was_prompted);
    }
    
    if (!err) {
        err = kim_identity_change_password_with_credential (inPrincipal,
                                                            credential, 
                                                            inNewPassword,
                                                            &context,
                                                            &rejected_err,
                                                            &rejected_message,
                                                            &rejected_description);
    }  
    
    if (!err) {
        *outRejected = (rejected_err != 0);
        if (rejected_err) {
            if (outRejectionError) {
                *outRejectionError = (char *) rejected_message;
                rejected_message = NULL;
            }
            if (outRejectionDescription) {
                *outRejectionDescription = (char *) rejected_description;
                rejected_description = NULL;
            }
        }
    }
    
    if (ui_inited) {
        kim_error fini_err = kim_ui_fini (&context);
        if (!err) { err = kl_check_error (fini_err); }
    }
    
    kim_string_free (&rejected_message);
    kim_string_free (&rejected_description);
    kim_credential_free (&credential);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

/* Application Configuration functions */

KLStatus KLSetIdleCallback (const KLIdleCallback inCallback,
                            const KLRefCon inRefCon)
{
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

KLStatus KLGetIdleCallback (KLIdleCallback* inCallback,
                            KLRefCon* inRefCon)
{
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

/* Library configuration functions */
/* Deprecated options which we now ignore */
enum {
    loginOption_ShowOptions                = 'sopt',
    loginOption_RememberShowOptions        = 'ropt',
    loginOption_LongTicketLifetimeDisplay  = 'hms ',
    loginOption_RememberPassword           = 'pass'
};


/* ------------------------------------------------------------------------ */

KLStatus KLGetDefaultLoginOption (const KLDefaultLoginOption  inOption,
                                  void                       *ioBuffer,
                                  KLSize                     *ioBufferSize)
{
    KLStatus  err = klNoErr;
    kim_preferences prefs = NULL;
    KLSize targetSize = 0;
    KLBoolean returnSizeOnly = (ioBuffer == NULL);
    
    if (!ioBufferSize) { err = kl_check_error (klParameterErr); }
    
    if (!err) {
        err = kim_preferences_create (&prefs);
    }
    
    if (!err && inOption == loginOption_LoginName) {
        kim_identity identity = NULL;
        kim_string string = "";
        
        err = kim_preferences_get_client_identity (prefs, &identity);
        
        if (!err && identity) {
            err = kim_identity_get_components_string (identity, &string);
        }
        
        if (!err) {
            targetSize = strlen (string);
            if (!returnSizeOnly) {
                if (*ioBufferSize < targetSize) {
                    err = kl_check_error (klBufferTooSmallErr);
                } else if (targetSize > 0) {
                    memmove (ioBuffer, string, targetSize);
                }
            }
        }
        
        if (string && string[0]) { kim_string_free (&string); }
        
    } else if (!err && inOption == loginOption_LoginInstance) {
        targetSize = 0; /* Deprecated */
        
    } else if (!err && (inOption == loginOption_ShowOptions ||
                        inOption == loginOption_RememberShowOptions ||
                        inOption == loginOption_LongTicketLifetimeDisplay ||
                        inOption == loginOption_RememberPrincipal ||
                        inOption == loginOption_RememberExtras ||
                        inOption == loginOption_RememberPassword)) {
        targetSize = sizeof(KLBoolean);
        
        if (!returnSizeOnly) {
            kim_boolean boolean = 0;
            
            if (inOption == loginOption_ShowOptions ||
                inOption == loginOption_RememberShowOptions ||
                inOption == loginOption_LongTicketLifetimeDisplay) {
                boolean = 1; /* Deprecated */
                
            } else if (inOption == loginOption_RememberPrincipal) {
                err = kim_preferences_get_remember_client_identity (prefs, &boolean);
                
            } else if (inOption == loginOption_RememberExtras) {
                err = kim_preferences_get_remember_options (prefs, &boolean);
                
            } else if (inOption == loginOption_RememberPassword) {
                boolean = kim_os_identity_allow_save_password ();
            }
            
            if (!err) {
                if (*ioBufferSize < targetSize) {
                    err = kl_check_error (klBufferTooSmallErr);
                } else {
                    *(KLBoolean *)ioBuffer = boolean;
                }
            }
        }
        
    } else if (!err && (inOption == loginOption_MinimalTicketLifetime ||
                        inOption == loginOption_MaximalTicketLifetime ||
                        inOption == loginOption_MinimalRenewableLifetime ||
                        inOption == loginOption_MaximalRenewableLifetime)) {
        targetSize = sizeof(KLLifetime);
        
        if (!returnSizeOnly) {
            kim_lifetime lifetime = 0;
            
            if (inOption == loginOption_MinimalTicketLifetime) {
                err = kim_preferences_get_minimum_lifetime (prefs, &lifetime);
                
            } else if (inOption == loginOption_MaximalTicketLifetime) {
                err = kim_preferences_get_maximum_lifetime (prefs, &lifetime);
                
            } else if (inOption == loginOption_MinimalRenewableLifetime) {
                err = kim_preferences_get_minimum_renewal_lifetime (prefs, &lifetime);
                
            } else if (inOption == loginOption_MaximalRenewableLifetime) {
                err = kim_preferences_get_maximum_renewal_lifetime (prefs, &lifetime);
            }   
            
            if (!err) {
                if (*ioBufferSize < targetSize) {
                    err = kl_check_error (klBufferTooSmallErr);
                } else {
                    *(KLLifetime *)ioBuffer = lifetime;
                }
            }
        }
        
    } else if (!err && (inOption == loginOption_DefaultRenewableTicket ||
                        inOption == loginOption_DefaultForwardableTicket ||
                        inOption == loginOption_DefaultProxiableTicket ||
                        inOption == loginOption_DefaultAddresslessTicket)) {
        targetSize = sizeof(KLBoolean);
        
        if (!returnSizeOnly) {
            kim_options options = NULL;
            kim_boolean boolean = 0;
            
            err = kim_preferences_get_options (prefs, &options);
            
            if (!err && inOption == loginOption_DefaultRenewableTicket) {
                err = kim_options_get_renewable (options, &boolean);
                
            } else if (!err && inOption == loginOption_DefaultForwardableTicket) {
                err = kim_options_get_forwardable (options, &boolean);
                
            } else if (!err && inOption == loginOption_DefaultProxiableTicket) {
                err = kim_options_get_proxiable (options, &boolean);
                
            } else if (!err && inOption == loginOption_DefaultAddresslessTicket) {
                err = kim_options_get_addressless (options, &boolean);
            }   
            
            if (!err) {
                if (*ioBufferSize < targetSize) {
                    err = kl_check_error (klBufferTooSmallErr);
                } else {
                    *(KLBoolean *)ioBuffer = boolean;
                }
            }
            
            kim_options_free (&options);
        }
        
        
    } else if (!err && (inOption == loginOption_DefaultTicketLifetime ||
                        inOption == loginOption_DefaultRenewableLifetime)) {
        targetSize = sizeof(KLLifetime);
        
        if (!returnSizeOnly) {
            kim_options options = NULL;
            kim_lifetime lifetime = 0;
            
            err = kim_preferences_get_options (prefs, &options);
            
            if (!err && inOption == loginOption_DefaultTicketLifetime) {
                err = kim_options_get_lifetime (options, &lifetime);
                
            } else if (!err && inOption == loginOption_DefaultRenewableLifetime) {
                err = kim_options_get_renewal_lifetime (options, &lifetime);
            }   
            
            if (!err) {
                if (*ioBufferSize < targetSize) {
                    err = kl_check_error (klBufferTooSmallErr);
                } else {
                    *(KLLifetime *)ioBuffer = lifetime;
                }
            }
            
            kim_options_free (&options);
        }
        
    } else { 
        err = kl_check_error (klInvalidOptionErr);
    }
    
    if (!err) {
        *ioBufferSize = targetSize;
    }
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLSetDefaultLoginOption (const KLDefaultLoginOption  inOption,
                                  const void                 *inBuffer,
                                  const KLSize                inBufferSize)
{
    KLStatus err = klNoErr;
    kim_preferences prefs = NULL;
    
    if (inBuffer == NULL) { err = kl_check_error (klParameterErr); }
    if (inBufferSize < 0) { err = kl_check_error (klParameterErr); }
    
    if (!err) {
        err = kim_preferences_create (&prefs);
    }
    
    if (!err && inOption == loginOption_LoginName) {
        kim_identity old_identity = NULL;
        kim_identity new_identity = NULL;
        kim_string new_identity_string = NULL;
        kim_string realm = NULL;
        kim_string components = NULL;
        
        err = kim_string_create_from_buffer (&components, inBuffer, inBufferSize);
        
        if (!err) {
            err = kim_preferences_get_client_identity (prefs, &old_identity);
            
            if (!err && old_identity) {
                err = kim_identity_get_realm (old_identity, &realm);
            }
        }
        
        if (!err && realm) {
            err = kim_string_create_from_format (&new_identity_string, 
                                                 "%s@%s", components, realm);
        }
        
        if (!err) {
            err = kim_identity_create_from_string (&new_identity,
                                                   (new_identity_string ?
                                                    new_identity_string :
                                                    components));
        }
        
        if (!err) {
            err = kim_preferences_set_client_identity (prefs, new_identity);
        }
        
        kim_string_free (&components);
        kim_string_free (&realm);
        kim_string_free (&new_identity_string);
        kim_identity_free (&old_identity);
        kim_identity_free (&new_identity);
        
    } else if (!err && inOption == loginOption_LoginInstance) {
        /* Ignored */
        
    } else if (!err && (inOption == loginOption_ShowOptions ||
                        inOption == loginOption_RememberShowOptions ||
                        inOption == loginOption_LongTicketLifetimeDisplay ||
                        inOption == loginOption_RememberPrincipal ||
                        inOption == loginOption_RememberExtras ||
                        inOption == loginOption_RememberPassword)) {
        if (inBufferSize > sizeof (KLBoolean)) {
            err = kl_check_error (klBufferTooLargeErr);
        } else if (inBufferSize < sizeof (KLBoolean)) {
            err = kl_check_error (klBufferTooSmallErr);
        }
        
        if (!err && inOption == loginOption_RememberPrincipal) {
            err = kim_preferences_set_remember_client_identity (prefs, *(KLBoolean *)inBuffer);
            
        } else if (!err && inOption == loginOption_RememberExtras) {
            err = kim_preferences_set_remember_options (prefs, *(KLBoolean *)inBuffer);
        }
        
    } else if (!err && (inOption == loginOption_MinimalTicketLifetime ||
                        inOption == loginOption_MaximalTicketLifetime ||
                        inOption == loginOption_MinimalRenewableLifetime ||
                        inOption == loginOption_MaximalRenewableLifetime)) {
        if (inBufferSize > sizeof (KLLifetime)) {
            err = kl_check_error (klBufferTooLargeErr);
        } else if (inBufferSize < sizeof (KLLifetime)) {
            err = kl_check_error (klBufferTooSmallErr);
        }
        
        if (!err && inOption == loginOption_MinimalTicketLifetime) {
            err = kim_preferences_set_minimum_lifetime (prefs, *(KLLifetime *)inBuffer);
            
        } else if (!err && inOption == loginOption_MaximalTicketLifetime) {
            err = kim_preferences_set_maximum_lifetime (prefs, *(KLLifetime *)inBuffer);
            
        } else if (!err && inOption == loginOption_MinimalRenewableLifetime) {
            err = kim_preferences_set_minimum_renewal_lifetime (prefs, *(KLLifetime *)inBuffer);
            
        } else if (!err && inOption == loginOption_MaximalRenewableLifetime) {
            err = kim_preferences_set_maximum_renewal_lifetime (prefs, *(KLLifetime *)inBuffer);
        }   
        
    } else if (!err && (inOption == loginOption_DefaultRenewableTicket ||
                        inOption == loginOption_DefaultForwardableTicket ||
                        inOption == loginOption_DefaultProxiableTicket ||
                        inOption == loginOption_DefaultAddresslessTicket)) {
        kim_options options = NULL;
        
        if (inBufferSize > sizeof (KLBoolean)) {
            err = kl_check_error (klBufferTooLargeErr);
        } else if (inBufferSize < sizeof (KLBoolean)) {
            err = kl_check_error (klBufferTooSmallErr);
        }
        
        if (!err) {
            err = kim_preferences_get_options (prefs, &options);
        }
        
        if (!err && inOption == loginOption_DefaultRenewableTicket) {
            err = kim_options_set_renewable (options, *(KLBoolean *)inBuffer);
            
        } else if (!err && inOption == loginOption_DefaultForwardableTicket) {
            err = kim_options_set_forwardable (options, *(KLBoolean *)inBuffer);
            
        } else if (!err && inOption == loginOption_DefaultProxiableTicket) {
            err = kim_options_set_proxiable (options, *(KLBoolean *)inBuffer);
            
        } else if (!err && inOption == loginOption_DefaultAddresslessTicket) {
            err = kim_options_set_addressless (options, *(KLBoolean *)inBuffer);
        }   
        
        if (!err) {
            err = kim_preferences_set_options (prefs, options);
        }
        
        kim_options_free (&options);
        
    } else if (!err && (inOption == loginOption_DefaultTicketLifetime ||
                        inOption == loginOption_DefaultRenewableLifetime)) {
        kim_options options = NULL;
        
        if (inBufferSize > sizeof (KLLifetime)) {
            err = kl_check_error (klBufferTooLargeErr);
        } else if (inBufferSize < sizeof (KLLifetime)) {
            err = kl_check_error (klBufferTooSmallErr);
        }
        
        if (!err) {
            err = kim_preferences_get_options (prefs, &options);
        }
        
        if (!err && inOption == loginOption_DefaultTicketLifetime) {
            err = kim_options_set_lifetime (options, *(KLLifetime *)inBuffer);
            
        } else if (!err && inOption == loginOption_DefaultRenewableLifetime) {
            err = kim_options_set_renewal_lifetime (options, *(KLLifetime *)inBuffer);
        }   
        
        if (!err) {
            err = kim_preferences_set_options (prefs, options);
        }
        
        kim_options_free (&options);
        
    } else { 
        err = kl_check_error (klInvalidOptionErr);
    }
    
    if (!err) {
        err = kim_preferences_synchronize (prefs);
    }    
    
    kim_preferences_free (&prefs);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

/* Realm configuration functions */

KLStatus KLFindKerberosRealmByName (const char *inRealmName,
                                    KLIndex    *outIndex)
{
    kim_error err = KIM_NO_ERROR;
    char *realm = NULL;
    
    if (!err) {
        err = KLGetKerberosDefaultRealmByName (&realm);
    }
    
    if (!err) {
        if (!strcmp (inRealmName, realm)) {
            *outIndex = 0;
        } else {
            err = kl_check_error (klRealmDoesNotExistErr);
        }
    }
    
    kim_string_free ((kim_string *) &realm);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLGetKerberosRealm (KLIndex   inIndex,
                             char    **outRealmName)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!outRealmName) { err = kl_check_error (klParameterErr); }
    if (!err && inIndex != 0) { err = kl_check_error (klRealmDoesNotExistErr); }
    
    if (!err) {
        err = KLGetKerberosDefaultRealmByName (outRealmName);
    }
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLSetKerberosRealm (KLIndex     inIndex,
                             const char *inRealmName)
{
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

KLStatus KLRemoveKerberosRealm (KLIndex inIndex)
{
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

KLStatus KLInsertKerberosRealm (KLIndex     inInsertBeforeIndex,
                                const char *inRealmName)
{
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

KLStatus KLRemoveAllKerberosRealms (void)
{
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

KLSize KLCountKerberosRealms (void)
{
    return 1;
}

/* ------------------------------------------------------------------------ */

KLStatus KLGetKerberosDefaultRealm(KLIndex *outIndex)
{
    kim_error err = KIM_NO_ERROR;
    
    if (!outIndex) { err = kl_check_error (klParameterErr); }
    
    if (!err) {
        *outIndex = 0;
    }
    
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

KLStatus KLGetKerberosDefaultRealmByName (char **outRealmName)
{
    kim_error err = KIM_NO_ERROR;
    krb5_context context = NULL;
    char *realm = NULL;
    
    if (!outRealmName) { err = kl_check_error (klParameterErr); }
    
    if (!err) {
        err = krb5_init_context (&context);
    }
    
    if (!err) {
    	err = krb5_get_default_realm(context, &realm);
    }
    
    if (!err) {
        err = kim_string_copy ((kim_string *) outRealmName, realm);
    }
    
    if (realm  ) { krb5_free_default_realm (context, realm); }
    if (context) { krb5_free_context (context); }
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLSetKerberosDefaultRealm (KLIndex inIndex)
{
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

KLStatus KLSetKerberosDefaultRealmByName (const char *inRealm)
{
    return kl_check_error (klNoErr);
}

/* ------------------------------------------------------------------------ */

/* KLPrincipal functions */

KLStatus KLCreatePrincipalFromTriplet (const char  *inName,
                                       const char  *inInstance,
                                       const char  *inRealm,
                                       KLPrincipal *outPrincipal)
{
    if (inInstance && strlen (inInstance) > 0) {
        return kl_check_error (kim_identity_create_from_components (outPrincipal,
                                                                    inRealm,
                                                                    inName, 
                                                                    inInstance,
                                                                    NULL));
    } else {
        return kl_check_error (kim_identity_create_from_components (outPrincipal,
                                                                    inRealm,
                                                                    inName, 
                                                                    NULL));        
    }
}

/* ------------------------------------------------------------------------ */

KLStatus KLCreatePrincipalFromString (const char        *inFullPrincipal,
                                      KLKerberosVersion  inKerberosVersion,
                                      KLPrincipal       *outPrincipal)
{
    return kl_check_error (kim_identity_create_from_string (outPrincipal, 
                                                            inFullPrincipal));
}

/* ------------------------------------------------------------------------ */

KLStatus KLCreatePrincipalFromKerberos5Principal (krb5_principal  inKerberos5Principal,
                                                  KLPrincipal    *outPrincipal)
{
    return kl_check_error (kim_identity_create_from_krb5_principal (outPrincipal, 
                                                                    NULL, /* context */
                                                                    inKerberos5Principal));
}

/* ------------------------------------------------------------------------ */

KLStatus KLCreatePrincipalFromPrincipal (KLPrincipal inPrincipal,
                                         KLPrincipal *outPrincipal)
{
    return kl_check_error (kim_identity_copy (outPrincipal, inPrincipal));
}

/* ------------------------------------------------------------------------ */

KLStatus KLGetTripletFromPrincipal (KLPrincipal   inPrincipal,
                                    char        **outName,
                                    char        **outInstance,
                                    char        **outRealm)
{
    KLStatus err = klNoErr;
    kim_string name = NULL;
    kim_string instance = NULL;
    kim_string realm = NULL;
    kim_count count = 0;
    
    if (!inPrincipal) { return kl_check_error (klBadPrincipalErr); }
    if (!outName    ) { return kl_check_error (klParameterErr); }
    if (!outInstance) { return kl_check_error (klParameterErr); }
    if (!outRealm   ) { return kl_check_error (klParameterErr); }
    
    if (!err) {
        err = kim_identity_get_number_of_components (inPrincipal, &count);
        if (!err && count > 2) { err = kl_check_error (klBadPrincipalErr); }
    }
    
    if (!err) {
        err = kim_identity_get_realm (inPrincipal, &realm);
    }
    
    if (!err) {
        err = kim_identity_get_component_at_index (inPrincipal, 0, &name);
    }
    
    if (!err && count > 1) {
        err = kim_identity_get_component_at_index (inPrincipal, 1, &instance);
    }
    
    if (!err) {
        *outName = (char *) name;
        name = NULL;
        *outInstance = (char *) instance;
        instance = NULL;
        *outRealm = (char *) realm;
        realm = NULL;
    }
    
    kim_string_free (&name);
    kim_string_free (&instance);
    kim_string_free (&realm);
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLGetStringFromPrincipal (KLPrincipal         inPrincipal,
                                   KLKerberosVersion   inKerberosVersion,
                                   char              **outFullPrincipal)
{
    return kl_check_error (kim_identity_get_string (inPrincipal, 
                                                    (kim_string *) outFullPrincipal));
}

/* ------------------------------------------------------------------------ */

KLStatus KLGetDisplayStringFromPrincipal (KLPrincipal         inPrincipal,
                                          KLKerberosVersion   inKerberosVersion,
                                          char              **outFullPrincipal)
{
    return kl_check_error (kim_identity_get_display_string (inPrincipal, 
                                                            (kim_string *) outFullPrincipal));
}

/* ------------------------------------------------------------------------ */

KLStatus KLComparePrincipal (KLPrincipal  inFirstPrincipal,
                             KLPrincipal  inSecondPrincipal,
                             KLBoolean   *outAreEquivalent)
{
    kim_error err = KIM_NO_ERROR;
    kim_comparison comparison;
    
    err = kim_identity_compare (inFirstPrincipal, inSecondPrincipal, 
                                &comparison);
    
    if (!err) {
        *outAreEquivalent = kim_comparison_is_equal_to (comparison);
    }
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLDisposePrincipal (KLPrincipal inPrincipal)
{
    kim_identity_free (&inPrincipal);
    return klNoErr;
}

/* ------------------------------------------------------------------------ */

/* KLLoginOptions functions */

KLStatus KLCreateLoginOptions (KLLoginOptions *outOptions)
{
    return kl_check_error (kim_options_create (outOptions));
}

/* ------------------------------------------------------------------------ */

KLStatus KLLoginOptionsSetTicketLifetime (KLLoginOptions ioOptions,
                                          KLLifetime     inTicketLifetime)
{
    return kl_check_error (kim_options_set_lifetime (ioOptions, inTicketLifetime));
}

/* ------------------------------------------------------------------------ */

KLStatus KLLoginOptionsSetForwardable (KLLoginOptions ioOptions,
                                       KLBoolean      inForwardable)
{
    return kl_check_error (kim_options_set_forwardable (ioOptions, inForwardable));
}

/* ------------------------------------------------------------------------ */

KLStatus KLLoginOptionsSetProxiable (KLLoginOptions ioOptions,
                                     KLBoolean      inProxiable)
{
    return kl_check_error (kim_options_set_proxiable (ioOptions, inProxiable));
}

/* ------------------------------------------------------------------------ */

KLStatus KLLoginOptionsSetRenewableLifetime (KLLoginOptions ioOptions,
                                             KLLifetime     inRenewableLifetime)
{
    KLStatus err = klNoErr;
    
    err = kim_options_set_renewable (ioOptions, inRenewableLifetime > 0);
    
    if (!err && inRenewableLifetime > 0) {
        err = kim_options_set_renewal_lifetime (ioOptions, inRenewableLifetime);
    } 
    
    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLStatus KLLoginOptionsSetAddressless (KLLoginOptions ioOptions,
                                       KLBoolean      inAddressless)
{
    return kl_check_error (kim_options_set_addressless (ioOptions, inAddressless));
}

/* ------------------------------------------------------------------------ */

KLStatus KLLoginOptionsSetTicketStartTime (KLLoginOptions ioOptions,
                                           KLTime         inStartTime)
{
    return kl_check_error (kim_options_set_start_time (ioOptions, inStartTime));
}

/* ------------------------------------------------------------------------ */

KLStatus KLLoginOptionsSetServiceName (KLLoginOptions  ioOptions,
                                       const char     *inServiceName)
{
    return kl_check_error (kim_options_set_service_name (ioOptions, inServiceName));
}

/* ------------------------------------------------------------------------ */

KLStatus KLDisposeLoginOptions(KLLoginOptions ioOptions)
{
    kim_options_free (&ioOptions);
    return klNoErr;
}

/* ------------------------------------------------------------------------ */

KLStatus KLDisposeString (char *inStringToDispose)
{
    kim_string_free ((kim_string *)&inStringToDispose);
    return klNoErr;
}

#pragma mark -

/* ------------------------------------------------------------------------ */

KLStatus __KLSetApplicationPrompter (KLPrompterProcPtr inPrompter)
{
    /* Deprecated */
    return klNoErr;
}

/* ------------------------------------------------------------------------ */

KLStatus __KLSetHomeDirectoryAccess (KLBoolean inAllowHomeDirectoryAccess)
{
    return kl_check_error (kim_library_set_allow_home_directory_access (inAllowHomeDirectoryAccess));
}

/* ------------------------------------------------------------------------ */

KLBoolean __KLAllowHomeDirectoryAccess (void)
{
    return kim_library_allow_home_directory_access ();
}

/* ------------------------------------------------------------------------ */

KLStatus __KLSetAutomaticPrompting (KLBoolean inAllowAutomaticPrompting)
{
    return kl_check_error (kim_library_set_allow_automatic_prompting (inAllowAutomaticPrompting));
}

/* ------------------------------------------------------------------------ */

KLBoolean __KLAllowAutomaticPrompting (void)
{
    return kl_check_error (kim_library_allow_automatic_prompting ());
}

/* ------------------------------------------------------------------------ */

KLStatus __KLSetPromptMechanism (KLPromptMechanism inPromptMechanism)
{
    kim_error err = KIM_NO_ERROR;

    if (inPromptMechanism == klPromptMechanism_None) {
        err = kim_library_set_allow_automatic_prompting (0);
    } else {
        err = kim_library_set_allow_automatic_prompting (1);
    }

    return kl_check_error (err);
}

/* ------------------------------------------------------------------------ */

KLPromptMechanism __KLPromptMechanism (void)
{
    kim_ui_environment environment = kim_library_ui_environment ();
    
    if (environment == KIM_UI_ENVIRONMENT_GUI) {
        return klPromptMechanism_GUI;
    } else if (environment == KIM_UI_ENVIRONMENT_CLI) {
        return klPromptMechanism_CLI;
    }
    return klPromptMechanism_None;
}

/* ------------------------------------------------------------------------ */

KLBoolean __KLAllowRememberPassword (void)
{
    return kl_check_error (kim_os_identity_allow_save_password ());
}

/* ------------------------------------------------------------------------ */

KLStatus __KLCreatePrincipalFromTriplet (const char  *inName,
                                         const char  *inInstance,
                                         const char  *inRealm,
                                         KLKerberosVersion  inKerberosVersion,
                                         KLPrincipal *outPrincipal)
{
    return kl_check_error (kim_identity_create_from_components (outPrincipal,
                                                                inRealm,
                                                                inName, 
                                                                inInstance,
                                                                NULL));
}

/* ------------------------------------------------------------------------ */

KLStatus __KLGetTripletFromPrincipal (KLPrincipal         inPrincipal,
                                      KLKerberosVersion   inKerberosVersion,
                                      char              **outName,
                                      char              **outInstance,
                                      char              **outRealm)
{
    return KLGetTripletFromPrincipal (inPrincipal, 
                                      outName, outInstance, outRealm);
}

/* ------------------------------------------------------------------------ */

KLStatus __KLCreatePrincipalFromKerberos5Principal (krb5_principal inPrincipal,
                                                    KLPrincipal *outPrincipal)
{
    return KLCreatePrincipalFromKerberos5Principal (inPrincipal, outPrincipal);
    
}

/* ------------------------------------------------------------------------ */

KLStatus __KLGetKerberos5PrincipalFromPrincipal (KLPrincipal     inPrincipal, 
                                                 krb5_context    inContext, 
                                                 krb5_principal *outKrb5Principal)
{
    return kl_check_error (kim_identity_get_krb5_principal (inPrincipal, 
                                                            inContext, 
                                                            outKrb5Principal));
}

/* ------------------------------------------------------------------------ */

KLBoolean __KLPrincipalIsTicketGrantingService (KLPrincipal inPrincipal)
{
    kim_boolean is_tgt = FALSE;
    kim_error err = kim_identity_is_tgt_service (inPrincipal, &is_tgt);
    
    return !err ? is_tgt : FALSE; 
}

/* ------------------------------------------------------------------------ */

KLStatus __KLGetKeychainPasswordForPrincipal (KLPrincipal   inPrincipal,
                                              char        **outPassword)
{
    return kl_check_error (kim_os_identity_get_saved_password (inPrincipal,
                                                               (kim_string *) outPassword));
}


/* ------------------------------------------------------------------------ */

KLStatus __KLPrincipalSetKeychainPassword (KLPrincipal  inPrincipal,
                                           const char  *inPassword)
{
    return kl_check_error (kim_os_identity_set_saved_password (inPrincipal,
                                                               inPassword));
}

/* ------------------------------------------------------------------------ */

KLStatus __KLRemoveKeychainPasswordForPrincipal (KLPrincipal inPrincipal)
{
    return kl_check_error (kim_os_identity_remove_saved_password (inPrincipal));
}

#pragma mark -

// ---------------------------------------------------------------------------

krb5_get_init_creds_opt *__KLLoginOptionsGetKerberos5Options (KLLoginOptions ioOptions)
{
    return kim_options_init_cred_options (ioOptions);
}

// ---------------------------------------------------------------------------

KLTime __KLLoginOptionsGetStartTime (KLLoginOptions ioOptions)
{
    return kim_options_start_time (ioOptions);
}

// ---------------------------------------------------------------------------

char *__KLLoginOptionsGetServiceName (KLLoginOptions ioOptions)
{
    return kim_options_service_name (ioOptions);
}



#endif /* KIM_TO_KLL_SHIM */

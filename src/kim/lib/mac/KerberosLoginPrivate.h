/*
* Copyright 1998-2008 Massachusetts Institute of Technology.
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

#ifndef __KERBEROSLOGINPRIVATE__
#define __KERBEROSLOGINPRIVATE__

#if defined(macintosh) || (defined(__MACH__) && defined(__APPLE__))
#    include <TargetConditionals.h>
#    if TARGET_RT_MAC_CFM
#        error "Use KfM 4.0 SDK headers for CFM compilation."
#    endif
#endif

#include <Kerberos/KerberosLogin.h>
#include <Kerberos/krb5.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    klPromptMechanism_Autodetect = 0,
    klPromptMechanism_GUI = 1,
    klPromptMechanism_CLI = 2,
    klPromptMechanism_None = 0xFFFFFFFF
};
typedef uint32_t KLPromptMechanism;

/*************/
/*** Types ***/
/*************/

#ifdef KERBEROSLOGIN_DEPRECATED

typedef krb5_error_code (*KLPrompterProcPtr) (krb5_context  context,
                                              void         *data,
                                              const char   *name,
                                              const char   *banner,
                                              int           num_prompts,
                                              krb5_prompt   prompts[]);
KLStatus __KLSetApplicationPrompter (KLPrompterProcPtr inPrompter);

#endif /* KERBEROSLOGIN_DEPRECATED */

/*****************/
/*** Functions ***/
/*****************/

KLStatus  __KLSetHomeDirectoryAccess (KLBoolean inAllowHomeDirectoryAccess);
KLBoolean __KLAllowHomeDirectoryAccess (void);

KLStatus  __KLSetAutomaticPrompting (KLBoolean inAllowAutomaticPrompting);
KLBoolean __KLAllowAutomaticPrompting (void);

KLBoolean __KLAllowRememberPassword (void);

KLStatus          __KLSetPromptMechanism (KLPromptMechanism inPromptMechanism);
KLPromptMechanism __KLPromptMechanism (void);

KLStatus __KLCreatePrincipalFromTriplet (const char  *inName,
                                         const char  *inInstance,
                                         const char  *inRealm,
                                         KLKerberosVersion  inKerberosVersion,
                                         KLPrincipal *outPrincipal);

KLStatus __KLGetTripletFromPrincipal (KLPrincipal         inPrincipal,
                                      KLKerberosVersion   inKerberosVersion,
                                      char              **outName,
                                      char              **outInstance,
                                      char              **outRealm);

KLStatus __KLCreatePrincipalFromKerberos5Principal (krb5_principal  inPrincipal,
                                                    KLPrincipal    *outPrincipal);

KLStatus __KLGetKerberos5PrincipalFromPrincipal (KLPrincipal     inPrincipal,
                                                 krb5_context    inContext,
                                                 krb5_principal *outKrb5Principal);

KLStatus __KLGetRealmFromPrincipal (KLPrincipal inPrincipal, char **outRealm);

KLBoolean __KLPrincipalIsTicketGrantingService (KLPrincipal inPrincipal);

KLStatus __KLGetKeychainPasswordForPrincipal (KLPrincipal   inPrincipal,
                                              char        **outPassword);

KLStatus __KLPrincipalSetKeychainPassword (KLPrincipal  inPrincipal,
                                           const char  *inPassword);

KLStatus __KLRemoveKeychainPasswordForPrincipal (KLPrincipal inPrincipal);

#if TARGET_OS_MAC
#    if defined(__MWERKS__)
#        pragma import reset
#    endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* __KERBEROSLOGINPRIVATE__ */

/*
 * Copyright (c) 2004 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/* $Id$ */

/* Adapted from multiple Leash header files */

#ifndef __KHIMAIRA_KRB5FUNCS_H
#define __KHIMAIRA_KRB5FUNCS_H

#include<stdlib.h>
#include<krb5.h>

#include <windows.h>
#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>

#include <krb5common.h>

#define LEASH_DEBUG_CLASS_GENERIC   0
#define LEASH_DEBUG_CLASS_KRB4      1
#define LEASH_DEBUG_CLASS_KRB4_APP  2

#define LEASH_PRIORITY_LOW  0
#define LEASH_PRIORITY_HIGH 1

#define KRB5_DEFAULT_LIFE            60*60*10 /* 10 hours */

// Function Prototypes.
BOOL khm_krb5_ms2mit(BOOL);

int
khm_krb5_kinit(krb5_context       alt_ctx,
               char *             principal_name,
               char *             password,
               krb5_deltat        lifetime,
               DWORD              forwardable,
               DWORD              proxiable,
               krb5_deltat        renew_life,
               DWORD              addressless,
               DWORD              publicIP,
               krb5_prompter_fct  prompter,
               void *             p_data
               );

long
Leash_int_kinit_ex(
    krb5_context ctx,
    HWND hParent,
    char * principal, 
    char * password, 
    int lifetime,
    int forwardable,
    int proxiable,
    int renew_life,
    int addressless,
    unsigned long publicIP,
    int displayErrors
    );

long
Leash_int_checkpwd(
    char * principal,
    char * password,
    int    displayErrors
    );

long
Leash_int_changepwd(
    char * principal, 
    char * password, 
    char * newpassword,
    char** result_string,
    int    displayErrors
    );

int
Leash_krb5_kdestroy(
    void
    );

int
Leash_krb5_kinit(
    krb5_context,
    HWND hParent,
    char * principal_name, 
    char * password,
    krb5_deltat lifetime,
    DWORD       forwardable,
    DWORD       proxiable,
    krb5_deltat renew_life,
    DWORD       addressless,
    DWORD       publicIP
    );

long
khm_convert524(
    krb5_context ctx
    );
    
int
Leash_afs_unlog(
    void
    );

int
Leash_afs_klog(
    char *, 
    char *, 
    char *, 
    int
    );

int 
LeashKRB5_renew(void);

LONG
write_registry_setting(
    char* setting,
    DWORD type,
    void* buffer,
    size_t size
    );

LONG
read_registry_setting_user(
    char* setting,
    void* buffer,
    size_t size
    );

LONG
read_registry_setting(
    char* setting,
    void* buffer,
    size_t size
    );

BOOL
get_STRING_from_registry(
    HKEY hBaseKey,
    char * key,
    char * value,
    char * outbuf,
    DWORD  outlen
    );

BOOL
get_DWORD_from_registry(
    HKEY hBaseKey,
    char * key,
    char * value,
    DWORD * result
    );

int
config_boolean_to_int(
    const char *s
    );


wchar_t * khm_krb5_get_default_realm(void);
wchar_t * khm_krb5_get_realm_list(void);
long khm_krb5_list_tickets(krb5_context *krbv5Context);
long khm_krb4_list_tickets(void);


#endif

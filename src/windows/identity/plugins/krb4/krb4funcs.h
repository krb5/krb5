/*
 * Copyright (c) 2005 Massachusetts Institute of Technology
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

#if _WIN32_WINNT < 0x0501
#define KHM_SAVE_WIN32_WINNT _WIN32_WINNT
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include<ntsecapi.h>
#ifdef KHM_SAVE_WIN32_WINNT
#undef _WIN32_WINNT
#define _WIN32_WINNT KHM_SAVE_WIN32_WINNT
#undef KHM_SAVE_WIN32_WINNT
#endif

#include <krb5common.h>

#define LEASH_DEBUG_CLASS_GENERIC   0
#define LEASH_DEBUG_CLASS_KRB4      1
#define LEASH_DEBUG_CLASS_KRB4_APP  2

#define LEASH_PRIORITY_LOW  0
#define LEASH_PRIORITY_HIGH 1

#define KRB5_DEFAULT_LIFE            60*60*10 /* 10 hours */


long
khm_convert524(khm_handle identity);

long
khm_krb4_kinit(char * aname,
               char * inst,
               char * realm,
               long lifetime,
               char * password);

long
khm_krb4_list_tickets(void);

int khm_krb4_kdestroy(void);

khm_handle
khm_krb4_find_tgt(khm_handle credset,
                  khm_handle identity);

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

void
khm_krb4_set_def_tkt_string(void);

wchar_t * khm_krb5_get_default_realm(void);
wchar_t * khm_krb5_get_realm_list(void);

#endif

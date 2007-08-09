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

#ifndef __KHIMAIRA_KCONFIGINTERNAL_H
#define __KHIMAIRA_KCONFIGINTERNAL_H

#define _NIMLIB_

#include<windows.h>
#include<kconfig.h>
#include<khlist.h>
#include<kherror.h>
#include<utils.h>
#include<strsafe.h>

/* TODO: Implement configuration provider interfaces

typedef struct kconf_provider_t {

} kconf_provider;
*/

typedef struct kconf_conf_space_t {
    wchar_t * name;

    /* kconf_provider * provider; */

    /* the regpath is the cumulative path starting from a hive root */
    wchar_t *   regpath;
    HKEY        regkey_user;
    khm_int32   regkey_user_flags;
    HKEY        regkey_machine;
    khm_int32   regkey_machine_flags;

    khm_int32   refcount;
    khm_int32   flags;

    const kconf_schema * schema;
    khm_int32   nSchema;

    TDCL(struct kconf_conf_space_t);
} kconf_conf_space;

#define KCONF_SPACE_FLAG_DELETE_U 0x00000040
#define KCONF_SPACE_FLAG_DELETE_M 0x00000080
#define KCONF_SPACE_FLAG_DELETED  0x00000100

typedef struct kconf_conf_handle_t {
    khm_int32   magic;
    khm_int32   flags;
    kconf_conf_space * space;

    struct kconf_conf_handle_t * lower;

    LDCL(struct kconf_conf_handle_t);
} kconf_handle;

#define KCONF_HANDLE_MAGIC 0x38eb49d2
#define khc_is_handle(h) ((h) && ((kconf_handle *)h)->magic == KCONF_HANDLE_MAGIC)
#define khc_shadow(h) (((kconf_handle *)h)->lower)
#define khc_is_shadowed(h) (khc_is_handle(h) && khc_shadow(h) != NULL)

extern kconf_conf_space * conf_root;
extern kconf_handle * conf_handles;
extern kconf_handle * conf_free_handles;
extern CRITICAL_SECTION cs_conf_global;
extern LONG conf_init;
extern LONG conf_status;

#define khc_is_config_running() (conf_init && conf_status)

#define CONFIG_REGPATHW L"Software\\MIT\\NetIDMgr"

void init_kconf(void);
void exit_kconf(void);

/* handle operations */
#define khc_space_from_handle(h)    (((kconf_handle *) h)->space)
#define khc_is_schema_handle(h)     (((kconf_handle *) h)->flags & KCONF_FLAG_SCHEMA)
#define khc_is_user_handle(h)       (((kconf_handle *) h)->flags & KCONF_FLAG_USER)
#define khc_is_machine_handle(h)    (((kconf_handle *) h)->flags & KCONF_FLAG_MACHINE)
#define khc_handle_flags(h)         (((kconf_handle *) h)->flags)

kconf_handle *
khcint_handle_from_space(kconf_conf_space * s, khm_int32 flags);

void
khcint_handle_free(kconf_handle * h);

kconf_conf_space *
khcint_create_empty_space(void);

void
khcint_free_space(kconf_conf_space * r);

void
khcint_space_hold(kconf_conf_space * s);

void
khcint_space_release(kconf_conf_space * s);

HKEY
khcint_space_open_key(kconf_conf_space * s, khm_int32 flags);

khm_int32
khcint_remove_space(kconf_conf_space * c, khm_int32 flags);

#endif

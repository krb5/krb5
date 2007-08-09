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

#ifndef __KHIMAIRA_KMMINTERNAL_H
#define __KHIMAIRA_KMMINTERNAL_H

#include<windows.h>
#include<shlwapi.h>
#include<strsafe.h>

#define KHERR_FACILITY kmm_facility
#define KHERR_FACILITY_ID KHM_FACILITY_KMM
#define KHERR_HMODULE ((HMODULE) kmm_hInstance)
#include<kherr.h>

#include<kmm.h>
#include<khmsgtypes.h>
#include<kherror.h>
#include<kplugin.h>

#define NOEXPORT

#include<utils.h>
#include<kconfig.h>
#include<kcreddb.h>
#include<kmm_msgs.h>

struct kmm_plugin_i_t; /* forward dcl */

typedef struct kmm_module_i_t {
    khm_int32 magic;

    wchar_t * name;
    wchar_t * path;
    wchar_t * description;
    wchar_t * vendor;
    wchar_t * support;

    khm_version file_version;
    khm_version prod_version;

    HMODULE h_module;

    HMODULE h_resource;
    WORD    lcid_resource;

    khm_int32 flags;
    khm_int32 state;
    khm_int32 plugin_count; /* number of active plugins */

    void * version_info;

    khm_int32 refcount;

    struct kmm_plugin_i_t * plugins; /* only used for registration */

    LDCL(struct kmm_module_i_t);
} kmm_module_i;

#define KMM_MODULE_MAGIC 0x482f4e88

#define kmm_is_module(m) ((m) && ((kmm_module_i *)m)->magic == KMM_MODULE_MAGIC)

#define kmm_module_from_handle(m) ((kmm_module_i *) m)
#define kmm_handle_from_module(m) ((kmm_module) m)

/* LoadLibrary succeeded for module */
#define KMM_MODULE_FLAG_LOADED      0x00000001

/* init_module entry called */
#define KMM_MODULE_FLAG_INITP       0x00000002

/* the resources have been loaded */
#define KMM_MODULE_FLAG_RES_LOADED  0x00000008

/* the signature has been verified */
#define KMM_MODULE_FLAG_SIG         0x00000010

/* the module is disabled by the user
   (option specified in configuration) */
#define KMM_MODULE_FLAG_DISABLED    0x00000400

/* the module should not be unloaded
   (option specified in configuration)*/
#define KMM_MODULE_FLAG_NOUNLOAD    0x00000800

/* the module has been removed from the active modules list. */
#define KMM_MODULE_FLAG_INACTIVE    0x00001000

typedef struct kmm_plugin_i_t {
    kmm_plugin_reg p;

    khm_int32   magic;

    kmm_module_i * module;
    HANDLE      ht_thread;
    DWORD       tid_thread;

    khm_int32   state;
    khm_int32   flags;
    
    int         refcount;

    int         n_depends;
    int         n_unresolved;
    struct kmm_plugin_i_t * dependants[KMM_MAX_DEPENDANTS];
    int         n_dependants;

    LDCL(struct kmm_plugin_i_t);
} kmm_plugin_i;

#define KMM_PLUGIN_MAGIC 0x320e8fb4

#define kmm_is_plugin(p) ((p) && ((kmm_plugin_i *) (p))->magic == KMM_PLUGIN_MAGIC)

#define kmm_handle_from_plugin(p) ((kmm_plugin) p)
#define kmm_plugin_from_handle(ph) ((kmm_plugin_i *) ph)

/* the plugin has already been marked for unload */
#define KMM_PLUGIN_FLAG_UNLOAD      0x00000001

/* the plugin is in the kmm_listed_plugins list */
#define KMM_PLUGIN_FLAG_IN_LIST     0x00000002

/* the plugin is in the module's plugin list */
#define KMM_PLUGIN_FLAG_IN_MODLIST  0x00000004

/* the plugin has been included in the pending_plugins count. */
#define KMM_PLUGIN_FLAG_IN_QUEUE    0x00000010

/* the plugin is included in the module's plugin count */
#define KMM_PLUGIN_FLAG_IN_MODCOUNT 0x00000020

/* the plugin is disabled by the user
    (option specified in configuration) */
/* (this is defined in kmm.h)

 #define KMM_PLUGIN_FLAG_DISABLED   0x00000400

*/

enum kmm_registrar_uparam_t {
    KMM_REG_INIT_MODULE,
    KMM_REG_EXIT_MODULE,
    KMM_REG_INIT_PLUGIN,
    KMM_REG_EXIT_PLUGIN
};

extern kmm_module_i * kmm_all_modules;
extern khm_size kmm_active_modules;
extern kmm_plugin_i * kmm_listed_plugins;
extern HANDLE ht_registrar;
extern DWORD tid_registrar;
extern DWORD tls_kmm;

extern hashtable * hash_plugins;
extern hashtable * hash_modules;

extern CRITICAL_SECTION cs_kmm;
extern int ready;
extern HANDLE evt_startup;
extern HANDLE evt_exit;
extern const wchar_t * kmm_facility;

extern HINSTANCE kmm_hInstance;

extern kconf_schema schema_kmmconfig[];

/* Registrar */

khm_boolean KHMAPI 
kmmint_reg_cb(khm_int32 msg_type, 
              khm_int32 msg_sub_type, 
              khm_ui_4 uparam,
              void *vparam);

DWORD WINAPI kmmint_registrar(LPVOID lpParameter);

DWORD WINAPI kmmint_plugin_broker(LPVOID lpParameter);

void kmmint_init_plugin(kmm_plugin_i * p);
void kmmint_exit_plugin(kmm_plugin_i * p);
void kmmint_init_module(kmm_module_i * m);
void kmmint_exit_module(kmm_module_i * m);

/* Modules */
kmm_module_i * 
kmmint_get_module_i(wchar_t * name);

kmm_module_i * 
kmmint_find_module_i(wchar_t * name);

void 
kmmint_free_module(kmm_module_i * m);

khm_int32
kmmint_read_module_info(kmm_module_i * m);

/* Plugins */
kmm_plugin_i * 
kmmint_get_plugin_i(wchar_t * name);

kmm_plugin_i * 
kmmint_find_plugin_i(wchar_t * name);

void 
kmmint_free_plugin(kmm_plugin_i * pi);

void 
kmmint_list_plugin(kmm_plugin_i * p);

void 
kmmint_delist_plugin(kmm_plugin_i * p);

khm_boolean 
kmmint_load_locale_lib(kmm_module_i * m, kmm_module_locale * l);

#define KMM_CSNAME_ROOT L"PluginManager"
#define KMM_CSNAME_PLUGINS L"Plugins"
#define KMM_CSNAME_MODULES L"Modules"
#define KMM_VALNAME_LOADLIST L"LoadList"

void
kmmint_add_to_module_queue(void);

void
kmmint_remove_from_module_queue(void);

#define _WAIT_FOR_START \
    do { \
    if(ready) break; \
    WaitForSingleObject(evt_startup, INFINITE); \
    } while(0)

#endif

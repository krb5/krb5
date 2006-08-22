/*
 * Copyright (c) 2006 Secure Endpoints Inc.
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

#include "credprov.h"

/* This file provides the entry points for the module.  The purpose of
   each entry point is explained below.
*/

kmm_module h_khModule;          /* KMM's handle to this module */
HINSTANCE hInstance;            /* handle to our DLL */
HMODULE hResModule;             /* handle to DLL containing language specific resources */

const wchar_t * my_facility = MYPLUGIN_FACILITYW;

/* locales and n_locales are used to provide information to NetIDMgr
   about the locales that we support.  Each locale that is supported
   is represented by a single line below.  NetIDMgr will pick a
   suitable locale from this list as described in the documentation
   for kmm_set_locale_info(). */
kmm_module_locale locales[] = {

    /* there needs to be at least one language that is supported.
       Here we declare that to be US English, and make it the
       default. */
    LOCALE_DEF(MAKELANGID(LANG_ENGLISH,SUBLANG_ENGLISH_US),
               MYPLUGIN_DLLBASEW L"_en_us.dll", /* this is the name of
                                                  the DLL. We paste a
                                                  trailer to basename
                                                  of the DLL.  This
                                                  DLL should reside in
                                                  the same directory
                                                  as the plugin
                                                  DLL. */
               KMM_MLOC_FLAG_DEFAULT)
};
int n_locales = ARRAYLENGTH(locales);

/*******************************************************************
   init_module
   *****************************************************************

   This is the entry point for the module.  Each module can provide
   multiple plugins and each plugin will need a separate entry point.
   Generally, the module entry point will set up localized resources
   and register the plugins.

*/
KHMEXP khm_int32 KHMAPI init_module(kmm_module h_module) {

    khm_int32 rv = KHM_ERROR_SUCCESS;
    kmm_plugin_reg pi;
    wchar_t description[KMM_MAXCCH_DESC];
    int t;

    h_khModule = h_module;

    rv = kmm_set_locale_info(h_module, locales, n_locales);
    if(KHM_SUCCEEDED(rv)) {
        /* if the call succeeded, then NetIDMgr has picked a localized
           resource DLL for us to use. */
        hResModule = kmm_get_resource_hmodule(h_module);
    } else
        goto _exit;

    /* TODO: Perform any other required initialization operations. */

    /* register our plugin */
    ZeroMemory(&pi, sizeof(pi));

    pi.name = MYPLUGIN_NAMEW;   /* name of the plugin */
    pi.type = KHM_PITYPE_CRED;  /* type.  This is a credentials
                                   provider.  Setting this type has
                                   the effect of having the plugin
                                   entrypoint being automatically
                                   subscribed to credentials provider
                                   messages. */

    /* An icon is optional, but we provide one anyway. */
    pi.icon = LoadImage(hResModule, MAKEINTRESOURCE(IDI_PLUGIN),
                        IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR | LR_DEFAULTSIZE);
    pi.flags = 0;
    pi.msg_proc = plugin_msg_proc;
    pi.description = description;
    pi.dependencies = NULL;
    t = LoadString(hResModule, IDS_PLUGIN_DESC,
                   description, ARRAYLENGTH(description));
    if (!t)
        description[0] = L'\0';
    else
        description[ARRAYLENGTH(description) - 1] = L'\0';

    rv = kmm_provide_plugin(h_module, &pi);

    /* TODO: register any additional plugins */

    /* Returning a successful code (KHM_ERROR_SUCCESS) will cause the
       plugins to be initialized.  If no plugin is successfully
       registered while processing init_module or if a code other than
       KHM_ERROR_SUCCESS is returned, the module will be immediately
       unloaded. */

 _exit:
    return rv;
}

/**********************************************************
   Exit module
   ********************************************************

   Called by the NetIDMgr module manager when unloading the module.
   This will get called even if the module is being unloaded due to an
   error code returned by init_module().  This callback is required. */
KHMEXP khm_int32 KHMAPI exit_module(kmm_module h_module) {

    /* Unregistering the plugin is not required at this point. */

    /* TODO: Perform any other required cleanup here. */

    return KHM_ERROR_SUCCESS; /* the return code is ignored */
}

/* General DLL initialization.  It is advisable to not do anything
   here and also keep in mind that the plugin will be loaded at a time
   where some threads have already started.  So DLL_THREAD_ATTACH will
   not fire for every thread.  In addition, the plugin will be
   unloaded before the application and all the threads terminate. */
BOOL WINAPI DllMain(HINSTANCE hinstDLL,
                    DWORD fdwReason,
                    LPVOID lpvReserved)
{
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:
            hInstance = hinstDLL;
            break;

        case DLL_PROCESS_DETACH:
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;
}

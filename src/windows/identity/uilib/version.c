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

#include<shlwapi.h>
#include<khuidefs.h>
#include<netidmgr_intver.h>

DLLVERSIONINFO ver_commctl;

static void
get_dll_version(wchar_t * dllname, DLLVERSIONINFO * pdvi) {
    HINSTANCE hdll;

    hdll = LoadLibrary(dllname);

    ZeroMemory(pdvi, sizeof(*pdvi));

    if(hdll) {
        DLLGETVERSIONPROC pDllGetVersion;

        pDllGetVersion = (DLLGETVERSIONPROC) GetProcAddress(hdll, "DllGetVersion");
        if(pDllGetVersion) {
            pdvi->cbSize = sizeof(*pdvi);

            (*pDllGetVersion)(pdvi);
        }
        FreeLibrary(hdll);
    }
}

KHMEXP void KHMAPI
khm_version_init(void) {
    get_dll_version(L"comctl32.dll", &ver_commctl);
}

KHMEXP void KHMAPI
khm_get_lib_version(khm_version * libver, khm_ui_4 * apiver) {
    if (!libver)
        return;

    libver->major = KH_VERSION_MAJOR;
    libver->minor = KH_VERSION_MINOR;
    libver->patch = KH_VERSION_PATCH;
    libver->aux = KH_VERSION_AUX;

    if (apiver)
        *apiver = KH_VERSION_API;
}

KHMEXP khm_ui_4 KHMAPI
khm_get_commctl_version(khm_version * pdvi) {
    if (pdvi) {
        pdvi->major = (khm_ui_2) ver_commctl.dwMajorVersion;
        pdvi->minor = (khm_ui_2) ver_commctl.dwMinorVersion;
        pdvi->patch = (khm_ui_2) ver_commctl.dwBuildNumber;
        pdvi->aux =   (khm_ui_2) ver_commctl.dwPlatformID;
    }

    return MAKELONG(ver_commctl.dwMinorVersion, ver_commctl.dwMajorVersion);
}

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

#ifndef __KHIMAIRA_REMOTE_H
#define __KHIMAIRA_REMOTE_H

/*! \addtogroup khui
  @{*/
/*! \defgroup khui_remote Connecting to NetIDMgr from another process
  @{*/

/* Leash compatibility */
#define ID_OBTAIN_TGT_WITH_LPARAM       32810

#define KHUI_REQDAEMONWND_CLASS L"IDMgrRequestDaemonCls"
#define KHUI_REQDAEMONWND_NAME  L"IDMgrRequestDaemon"

#define KHUI_REQD_MAPPING_FORMAT L"Local\\NetIDMgr_DlgInfo_%lu"

#define NETID_USERNAME_SZ       128
#define NETID_REALM_SZ          192
#define NETID_TITLE_SZ          256
#define NETID_CCACHE_NAME_SZ    264

#define NETID_DLGTYPE_TGT      0
#define NETID_DLGTYPE_CHPASSWD 1
typedef struct {
    DWORD size;
    DWORD dlgtype;
    // Tells whether dialog box is in change pwd mode or init ticket mode
    struct {
        WCHAR title[NETID_TITLE_SZ];
        WCHAR username[NETID_USERNAME_SZ];
        WCHAR realm[NETID_REALM_SZ];
        WCHAR ccache[NETID_CCACHE_NAME_SZ];
        DWORD use_defaults;
        DWORD forwardable;
        DWORD noaddresses;
        DWORD lifetime;
        DWORD renew_till;
        DWORD proxiable;
        DWORD publicip;
        DWORD must_use_specified_principal;
    } in;
    struct {
        WCHAR username[NETID_USERNAME_SZ];
        WCHAR realm[NETID_REALM_SZ];
        WCHAR ccache[NETID_CCACHE_NAME_SZ];
    } out;
    // Version 1 of this structure ends here
} NETID_DLGINFO, *LPNETID_DLGINFO;

#define NETID_DLGINFO_V1_SZ (10 * sizeof(DWORD) \
         + sizeof(WCHAR) * (NETID_TITLE_SZ + \
         2 * NETID_USERNAME_SZ + 2 * NETID_REALM_SZ + \
         2 * NETID_CCACHE_NAME_SZ))

/*!@} */
/*!@} */

#endif

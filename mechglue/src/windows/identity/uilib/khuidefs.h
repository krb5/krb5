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

#ifndef __KHIMAIRA_KHUIDEFS_H
#define __KHIMAIRA_KHUIDEFS_H

#include<windows.h>
#include<kmq.h>
#include<kcreddb.h>
#include<kherror.h>
#include<kherr.h>
#include<khmsgtypes.h>

#include<khaction.h>
#include<khactiondef.h>
#include<khrescache.h>
#include<khhtlink.h>
#include<khnewcred.h>
#include<khprops.h>
#include<khalerts.h>
#include<khconfigui.h>
#include<khtracker.h>

#include<khremote.h>

#include<strsafe.h>

/*! \internal */
KHMEXP void KHMAPI
khm_version_init(void);

/*! \defgroup khui User Interface

    Functions and data structures for interacting with the user
    interface.

@{*/

/*! \brief Get the version of the NetIDMgr library

    \param[out] libver Receives the version of the library.

    \param[out] apiver Receives the API version of the library.
        Optional.  Set to NULL if this value is not required.

    \note When the NetIDMgr framework loads a plugin, it checks the
        version information of the plugin against the version of the
        library to determine if the plugin is compatible.
 */
KHMEXP void KHMAPI
khm_get_lib_version(khm_version * libver, khm_ui_4 * apiver);

/*! \brief Return the version of Common Control library

    Can be used to check the version of the Windows Common Control
    library that is currently loaded.  The return value of the
    function is the packed version value obatained by the macro :

    \code
    MAKELONG(vesion->dwMinorVersion, version->dwMajorVersion);
    \endcode

    The \a pdvi parameter is optional.  Specify NULL if this is not
    required.
 */
KHMEXP khm_ui_4 KHMAPI
khm_get_commctl_version(khm_version * pdvi);

/*!@}*/

#endif

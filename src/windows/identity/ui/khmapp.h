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

#ifndef __KHIMAIRA_KHIMAIRA_H
#define __KHIMAIRA_KHIMAIRA_H

#include<windows.h>
#include<windowsx.h>
#include<strsafe.h>
#include<commctrl.h>
#include<htmlhelp.h>

#define KHERR_HMODULE khm_hInstance
#define KHERR_FACILITY khm_facility
#define KHERR_FACILITY_ID 3

#define NOEXPORT

#include<netidmgr.h>

#include<khhelp.h>
#include<intaction.h>
#include<intalert.h>

#include<resource.h>
#include<credfuncs.h>
#include<appglobal.h>
#include<mainwnd.h>
#include<mainmenu.h>
#include<toolbar.h>
#include<statusbar.h>
#include<credwnd.h>
#include<htwnd.h>
#include<passwnd.h>
#include<newcredwnd.h>
#include<propertywnd.h>
#include<configwnd.h>
#include<aboutwnd.h>
#include<debugfuncs.h>
#include<taskbar.h>

#include<reqdaemon.h>
#include<notifier.h>
#include<timer.h>
#include<addrchange.h>

#endif

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

#ifndef __KHIMAIRA_KCREDDBINTERNAL_H__
#define __KHIMAIRA_KCREDDBINTERNAL_H__

#define _NIMLIB_

#include<windows.h>
#include<kcreddb.h>
#include<kmq.h>
#include<khlist.h>
#include<utils.h>
#include<kherror.h>
#include<khmsgtypes.h>
#include<kconfig.h>
#include<strsafe.h>

#include<langres.h>

#include "buf.h"
#include "identity.h"
#include "attrib.h"
#include "type.h"
#include "credential.h"
#include "credset.h"
#include "credtype.h"

/* globals */

extern HINSTANCE hinst_kcreddb;

kconf_schema schema_kcdbconfig[];

void kcdb_init(void);
void kcdb_exit(void);
khm_handle kcdb_get_config(void);


#endif

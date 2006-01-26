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

#ifndef __KHIMAIRA_CREDFUNCS_H
#define __KHIMAIRA_CREDFUNCS_H

void KHMAPI 
kmsg_cred_completion(kmq_message *m);

void 
khm_cred_destroy_creds(void);

void 
khm_cred_renew_identity(khm_handle identity);

void 
khm_cred_renew_cred(khm_handle cred);

void 
khm_cred_renew_creds(void);

void 
khm_cred_obtain_new_creds(wchar_t * window_title);

void 
khm_cred_set_default(void);

void 
khm_cred_change_password(wchar_t * window_title);

void 
khm_cred_dispatch_process_message(khui_new_creds *nc);

BOOL 
khm_cred_dispatch_process_level(khui_new_creds *nc);

BOOL
khm_cred_is_in_dialog(void);

khm_int32
khm_cred_wait_for_dialog(DWORD timeout, khm_int32 * result,
                         wchar_t * ident, khm_size cb_ident);

void
khm_cred_begin_commandline(void);

void
khm_cred_process_commandline(void);

void
khm_cred_refresh(void);

void
khm_cred_addr_change(void);

void
khm_cred_import(void);

#endif

/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * $Id$
 */

#ifndef _GSSMISC_H_
#define _GSSMISC_H_

#include <gssapi/gssapi_generic.h>
#include <stdio.h>

extern FILE *display_file;

int send_token
	PROTOTYPE( (int s, gss_buffer_t tok) );
int recv_token
	PROTOTYPE( (int s, gss_buffer_t tok) );
void display_status
	PROTOTYPE( (char *msg, OM_uint32 maj_stat, OM_uint32 min_stat) );
void display_ctx_flags
	PROTOTYPE( (OM_uint32 flags) );
void print_token
	PROTOTYPE( (gss_buffer_t tok) );

#endif

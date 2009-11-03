/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $Id: windc_plugin.h 22693 2008-03-19 08:57:49Z lha $ */

#ifndef HEIMDAL_WINDC_PLUGIN_H
#define HEIMDAL_WINDC_PLUGIN_H 1

/*
 * The PAC generate function should allocate a heim_pac using
 * heim_pac_init and fill in the PAC structure for the principal using
 * heim_pac_add_buffer.
 *
 * The PAC verify function should verify all components in the PAC
 * using heim_pac_get_types and heim_pac_get_buffer for all types.
 *
 * Check client access function check if the client is authorized.
 */

struct hdb_entry_ex;

struct _heim_pac_data;
typedef struct _heim_pac_data *heim_pac;

typedef krb5_error_code
(*krb5plugin_windc_pac_generate)(void *, heim_context,
				 struct hdb_entry_ex *, heim_pac *);

typedef krb5_error_code
(*krb5plugin_windc_pac_verify)(void *, heim_context,
			       const Principal *,
			       struct hdb_entry_ex *,
			       struct hdb_entry_ex *,
			       heim_pac *);
typedef krb5_error_code
(*krb5plugin_windc_client_access)(
    void *, heim_context, struct hdb_entry_ex *, KDC_REQ *, heim_octet_string *);


#define KRB5_WINDC_PLUGIN_MINOR		3

typedef struct krb5plugin_windc_ftable {
    int			minor_version;
    krb5_error_code	(*init)(heim_context, void **);
    void		(*fini)(void *);
    krb5plugin_windc_pac_generate	pac_generate;
    krb5plugin_windc_pac_verify		pac_verify;
    krb5plugin_windc_client_access	client_access;
} krb5plugin_windc_ftable;

#endif /* HEIMDAL_WINDC_PLUGIN_H */

/*
 * kdc/kdc_authdata.c
 *
 * Copyright (C) 2007 Apple Inc.  All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 * AuthorizationData routines for the KDC.
 */

#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"
#include <stdio.h>
#include "adm_proto.h"

#include <syslog.h>

#include <assert.h>
#include "../include/krb5/authdata_plugin.h"

#if TARGET_OS_MAC
static const char *objdirs[] = { KRB5_AUTHDATA_PLUGIN_BUNDLE_DIR, LIBDIR "/krb5/plugins/authdata", NULL }; /* should be a list */
#else
static const char *objdirs[] = { LIBDIR "/krb5/plugins/authdata", NULL };
#endif

typedef krb5_error_code (*authdata_proc)
    (krb5_context, krb5_db_entry *client,
     krb5_data *req_pkt,
     krb5_kdc_req *request,
     krb5_enc_tkt_part * enc_tkt_reply);

typedef krb5_error_code (*init_proc)
    (krb5_context, void **);
typedef void (*fini_proc)
    (krb5_context, void *);

typedef struct _krb5_authdata_systems {
    const char *name;
    int         type;
    int         flags;
    void       *plugin_context;
    init_proc   init;
    fini_proc   fini;
    authdata_proc handle_authdata;
} krb5_authdata_systems;

#undef GREET_PREAUTH

#ifdef GREET_PREAUTH
static krb5_error_code
greet_init(krb5_context ctx, void **blob)
{
    *blob = "hello";
    return 0;
}

static void
greet_fini(krb5_context ctx, void *blob)
{
}

static krb5_error_code
greet_authdata(krb5_context ctx, krb5_db_entry *client,
	       krb5_data *req_pkt,
	       krb5_kdc_req *request,
	       krb5_enc_tkt_part * enc_tkt_reply)
{
#define GREET_SIZE (20)

    char *p;
    krb5_authdata *a;
    size_t count;
    krb5_authdata **new_ad;

    krb5_klog_syslog (LOG_DEBUG, "in greet_authdata");

    p = calloc(1, GREET_SIZE);
    a = calloc(1, sizeof(*a));

    if (p == NULL || a == NULL) {
	free(p);
	free(a);
	return ENOMEM;
    }
    strlcpy(p, "hello", GREET_SIZE);
    a->magic = KV5M_AUTHDATA;
    a->ad_type = -42;
    a->length = GREET_SIZE;
    a->contents = p;
    if (enc_tkt_reply->authorization_data == 0) {
	count = 0;
    } else {
	for (count = 0; enc_tkt_reply->authorization_data[count] != 0; count++)
	    ;
    }
    new_ad = realloc(enc_tkt_reply->authorization_data,
		     (count+2) * sizeof(krb5_authdata *));
    if (new_ad == NULL) {
	free(p);
	free(a);
	return ENOMEM;
    }
    enc_tkt_reply->authorization_data = new_ad;
    new_ad[count] = a;
    new_ad[count+1] = NULL;
    return 0;
}
#endif

static krb5_authdata_systems static_authdata_systems[] = {
#ifdef GREET_PREAUTH
    { "greeting", 0, 0, 0, greet_init, greet_fini, greet_authdata },
#endif
    { "[end]", -1,}
};

static krb5_authdata_systems *authdata_systems;
static int n_authdata_systems;
static struct plugin_dir_handle authdata_plugins;

krb5_error_code
load_authdata_plugins(krb5_context context)
{
    void **authdata_plugins_ftables = NULL;
    struct krb5plugin_authdata_ftable_v0 *ftable = NULL;
    size_t module_count;
    int i, k;
    init_proc server_init_proc = NULL;

    /* Attempt to load all of the authdata plugins we can find. */
    PLUGIN_DIR_INIT(&authdata_plugins);
    if (PLUGIN_DIR_OPEN(&authdata_plugins) == 0) {
	if (krb5int_open_plugin_dirs(objdirs, NULL,
				     &authdata_plugins, &context->err) != 0) {
	    return KRB5_PLUGIN_NO_HANDLE;
	}
    }

    /* Get the method tables provided by the loaded plugins. */
    authdata_plugins_ftables = NULL;
    n_authdata_systems = 0;
    if (krb5int_get_plugin_dir_data(&authdata_plugins,
				    "authdata_server_0",
				    &authdata_plugins_ftables, &context->err) != 0) {
	return KRB5_PLUGIN_NO_HANDLE;
    }

    /* Count the valid modules. */ 
    module_count = sizeof(static_authdata_systems)
	/ sizeof(static_authdata_systems[0]);
    if (authdata_plugins_ftables != NULL) {
	for (i = 0; authdata_plugins_ftables[i] != NULL; i++) {
	    ftable = authdata_plugins_ftables[i];
	    if ((ftable->authdata_proc != NULL)) {
		module_count++;
	    }
	}
    }

    /* Build the complete list of supported authdata options, and
     * leave room for a terminator entry. */
    authdata_systems = calloc(module_count + 1, sizeof(krb5_authdata_systems));
    if (authdata_systems == NULL) {
	krb5int_free_plugin_dir_data(authdata_plugins_ftables);
	return ENOMEM;
    }

    /* Add the locally-supplied mechanisms to the dynamic list first. */
    for (i = 0, k = 0;
	 i < sizeof(static_authdata_systems) / sizeof(static_authdata_systems[0]);
	 i++) {
	if (static_authdata_systems[i].type == -1)
	    break;
	authdata_systems[k] = static_authdata_systems[i];
	/* Try to initialize the authdata system.  If it fails, we'll remove it
	 * from the list of systems we'll be using. */
	server_init_proc = static_authdata_systems[i].init;
	if ((server_init_proc != NULL) &&
	    ((*server_init_proc)(context, &authdata_systems[k].plugin_context) != 0)) {
	    memset(&authdata_systems[k], 0, sizeof(authdata_systems[k]));
	    continue;
	}
	k++;
    }

    /* Now add the dynamically-loaded mechanisms to the list. */
    if (authdata_plugins_ftables != NULL) {
	for (i = 0; authdata_plugins_ftables[i] != NULL; i++) {
	    krb5_error_code initerr;
	    void *pctx = NULL;

	    ftable = authdata_plugins_ftables[i];
	    if ((ftable->authdata_proc == NULL)) {
		continue;
	    }
	    server_init_proc = ftable->init_proc;
	    if ((server_init_proc != NULL) &&
		((initerr = (*server_init_proc)(context, &pctx)) != 0)) {
		const char *emsg;
		emsg = krb5_get_error_message(context, initerr);
		if (emsg) {
		    krb5_klog_syslog(LOG_ERR,
				     "authdata %s failed to initialize: %s",
				     ftable->name, emsg);
		    krb5_free_error_message(context, emsg);
		}
		memset(&authdata_systems[k], 0, sizeof(authdata_systems[k]));
	
		continue;
	    }
    
	    authdata_systems[k].name = ftable->name;
	    authdata_systems[k].init = server_init_proc;
	    authdata_systems[k].fini = ftable->fini_proc;
	    authdata_systems[k].handle_authdata = ftable->authdata_proc;
	    authdata_systems[k].plugin_context = pctx;
	    k++;
	}
	krb5int_free_plugin_dir_data(authdata_plugins_ftables);
    }
    n_authdata_systems = k;
    /* Add the end-of-list marker. */
    authdata_systems[k].name = "[end]";
    authdata_systems[k].type = -1;
    return 0;
}

krb5_error_code
unload_authdata_plugins(krb5_context context)
{
    int i;
    if (authdata_systems != NULL) {
	for (i = 0; i < n_authdata_systems; i++) {
	    if (authdata_systems[i].fini != NULL) {
		(*authdata_systems[i].fini)(context,
					    authdata_systems[i].plugin_context);
	    }
	    memset(&authdata_systems[i], 0, sizeof(authdata_systems[i]));
	}
	free(authdata_systems);
	authdata_systems = NULL;
	n_authdata_systems = 0;
	krb5int_close_plugin_dirs(&authdata_plugins);
    }
    return 0;
}

krb5_error_code
handle_authdata (krb5_context context, krb5_db_entry *client,
		 krb5_data *req_pkt, krb5_kdc_req *request,
		 krb5_enc_tkt_part *enc_tkt_reply)
{
    krb5_error_code retval = 0;
    int i;
    const char *emsg;

    krb5_klog_syslog (LOG_DEBUG, "handling authdata");

    for (i = 0; i < n_authdata_systems; i++) {
	const krb5_authdata_systems *asys = &authdata_systems[i];
	if (asys->handle_authdata && asys->type != -1) {
	    retval = asys->handle_authdata(context, client, req_pkt,
					   request, enc_tkt_reply);
	    if (retval) {
		emsg = krb5_get_error_message (context, retval);
		krb5_klog_syslog (LOG_INFO,
				  "authdata (%s) handling failure: %s",
				  asys->name, emsg);
		krb5_free_error_message (context, emsg);
	    } else {
		krb5_klog_syslog (LOG_DEBUG, ".. .. ok");
	    }
	}
    }

    return 0;
}

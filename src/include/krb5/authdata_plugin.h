/*
 * krb5/authdata_plugin.h
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
 * AuthorizationData plugin definitions for Kerberos 5.
 */

/*
 * This is considered an INTERNAL interface at this time.
 *
 * Some work is needed before exporting it:
 *
 * + Documentation.
 * + Sample code.
 * + Test cases (preferably automated testing under "make check").
 * + Hook into TGS exchange too; will change API.
 * + Examine memory management issues, especially for Windows; may
 *   change API.
 *
 * Other changes that would be nice to have, but not necessarily
 * before making this interface public:
 *
 * + Library support for AD-IF-RELEVANT and similar wrappers.  (We can
 *   make the plugin construct them if it wants them.)
 * + KDC could combine/optimize wrapped AD elements provided by
 *   multiple plugins, e.g., two IF-RELEVANT sequences could be
 *   merged.  (The preauth plugin API also has this bug, we're going
 *   to need a general fix.)
 */

#ifndef KRB5_AUTHDATA_PLUGIN_H_INCLUDED
#define KRB5_AUTHDATA_PLUGIN_H_INCLUDED
#include <krb5/krb5.h>

/*
 * While arguments of these types are passed-in, for the most part a
 * authorization data module can treat them as opaque.  If we need
 * keying data, we can ask for it directly.
 */
struct _krb5_db_entry_new;

/*
 * The function table / structure which an authdata server module must export as
 * "authdata_server_0".  NOTE: replace "0" with "1" for the type and
 * variable names if this gets picked up by upstream.  If the interfaces work
 * correctly, future versions of the table will add either more callbacks or
 * more arguments to callbacks, and in both cases we'll be able to wrap the v0
 * functions.
 */
/* extern krb5plugin_authdata_ftable_v0 authdata_server_0; */
typedef struct krb5plugin_authdata_ftable_v0 {
    /* Not-usually-visible name. */
    char *name;

    /*
     * Per-plugin initialization/cleanup.  The init function is called
     * by the KDC when the plugin is loaded, and the fini function is
     * called before the plugin is unloaded.  Both are optional.
     */
    krb5_error_code (*init_proc)(krb5_context, void **);
    void (*fini_proc)(krb5_context, void *);
    /*
     * Actual authorization data handling function.  If this field
     * holds a null pointer, this mechanism will be skipped, and the
     * init/fini functions will not be run.
     *
     * This function should only modify the field
     * enc_tkt_reply->authorization_data.  All other values should be
     * considered inputs only.  And, it should *modify* the field, not
     * overwrite it and assume that there are no other authdata
     * plugins in use.
     *
     * Memory management: authorization_data is a malloc-allocated,
     * null-terminated sequence of malloc-allocated pointers to
     * authorization data structures.  This plugin code currently
     * assumes the libraries, KDC, and plugin all use the same malloc
     * pool, which may be a problem if/when we get the KDC code
     * running on Windows.
     *
     * If this function returns a non-zero error code, a message
     * is logged, but no other action is taken.  Other authdata
     * plugins will be called, and a response will be sent to the
     * client (barring other problems).
     */
    krb5_error_code (*authdata_proc)(krb5_context,
				     struct _krb5_db_entry_new *client,
				     krb5_data *req_pkt,
				     krb5_kdc_req *request,
				     krb5_enc_tkt_part *enc_tkt_reply);
} krb5plugin_authdata_ftable_v0;
#endif /* KRB5_AUTHDATA_PLUGIN_H_INCLUDED */

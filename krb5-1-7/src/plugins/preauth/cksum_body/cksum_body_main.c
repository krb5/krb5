/*
 * Copyright (C) 2006 Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Red Hat, Inc., nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Checksum the request body with the user's long-term key.
 *
 * The e-data from the KDC is a list of network-byte-order 32-bit integers
 * listing key types which the KDC has for the user.
 *
 * The client uses one of these key types to generate a checksum over the body
 * of the request, and includes the checksum in the AS-REQ as preauthentication
 * data.
 *
 * The AS-REP carries no preauthentication data for this scheme.
 */

#ident "$Id: cksum_body_main.c,v 1.4 2007/01/02 22:33:50 kwc Exp $"

#include "autoconf.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <arpa/inet.h>
#include <stdio.h>

#include <krb5/krb5.h>
#include <krb5/preauth_plugin.h>

/* This is not a standardized value.  It's defined here only to make it easier
 * to change in this module. */
#define KRB5_PADATA_CKSUM_BODY_REQ 130

struct server_stats{
    int successes, failures;
};

typedef struct _test_svr_req_ctx {
    int value1;
    int value2;
} test_svr_req_ctx;

static int
client_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_REAL;
}

static krb5_error_code
client_process(krb5_context kcontext,
	       void *client_plugin_context,
	       void *client_request_context,
	       krb5_get_init_creds_opt *opt,
	       preauth_get_client_data_proc client_get_data_proc,
	       struct _krb5_preauth_client_rock *rock,
	       krb5_kdc_req *request,
	       krb5_data *encoded_request_body,
	       krb5_data *encoded_previous_request,
	       krb5_pa_data *pa_data,
	       krb5_prompter_fct prompter,
	       void *prompter_data,
	       preauth_get_as_key_proc gak_fct,
	       void *gak_data,
	       krb5_data *salt, krb5_data *s2kparams,
	       krb5_keyblock *as_key,
	       krb5_pa_data ***out_pa_data)
{
    krb5_pa_data **send_pa;
    krb5_checksum checksum;
    krb5_enctype enctype;
    krb5_cksumtype *cksumtypes;
    krb5_error_code status = 0;
    krb5_int32 cksumtype, *enctypes;
    unsigned int i, n_enctypes, cksumtype_count;
    int num_gic_info = 0;
    krb5_gic_opt_pa_data *gic_info;

    status = krb5_get_init_creds_opt_get_pa(kcontext, opt,
					    &num_gic_info, &gic_info);
    if (status && status != ENOENT) {
#ifdef DEBUG
	fprintf(stderr, "Error from krb5_get_init_creds_opt_get_pa: %s\n",
		error_message(status));
#endif
	return status;
    }
#ifdef DEBUG
    fprintf(stderr, "(cksum_body) Got the following gic options:\n");
#endif
    for (i = 0; i < num_gic_info; i++) {
#ifdef DEBUG
	fprintf(stderr, "  '%s' = '%s'\n", gic_info[i].attr, gic_info[i].value);
#endif
    }
    krb5_get_init_creds_opt_free_pa(kcontext, num_gic_info, gic_info);

    memset(&checksum, 0, sizeof(checksum));

    /* Get the user's long-term key if we haven't asked for it yet.  Try
     * all of the encryption types which the server supports. */
    if (as_key->length == 0) {
	if ((pa_data != NULL) && (pa_data->length >= 4)) {
#ifdef DEBUG
	    fprintf(stderr, "%d bytes of preauth data.\n", pa_data->length);
#endif
	    n_enctypes = pa_data->length / 4;
	    enctypes = (krb5_int32*) pa_data->contents;
	} else {
	    n_enctypes = request->nktypes;
	}
	for (i = 0; i < n_enctypes; i++) {
	    if ((pa_data != NULL) && (pa_data->length >= 4)) {
		memcpy(&enctype, pa_data->contents + 4 * i, 4);
		enctype = ntohl(enctype);
	    } else {
		enctype = request->ktype[i];
	    }
#ifdef DEBUG
	    fprintf(stderr, "Asking for AS key (type = %d).\n", enctype);
#endif
	    status = (*gak_fct)(kcontext, request->client, enctype,
				prompter, prompter_data,
				salt, s2kparams, as_key, gak_data);
	    if (status == 0)
		break;
	}
	if (status != 0)
	    return status;
    }
#ifdef DEBUG
    fprintf(stderr, "Got AS key (type = %d).\n", as_key->enctype);
#endif

    /* Determine an appropriate checksum type for this key. */
    cksumtype_count = 0;
    cksumtypes = NULL;
    status = krb5_c_keyed_checksum_types(kcontext, as_key->enctype,
					 &cksumtype_count, &cksumtypes);
    if (status != 0)
	return status;

    /* Generate the checksum. */
    for (i = 0; i < cksumtype_count; i++) {
	status = krb5_c_make_checksum(kcontext, cksumtypes[i], as_key,
				      KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
				      encoded_request_body,
				      &checksum);
	if (status == 0) {
#ifdef DEBUG
	    fprintf(stderr, "Made checksum (type = %d, %d bytes).\n",
		    checksum.checksum_type, encoded_request_body->length);
#endif
	    break;
	}
    }
    cksumtype = htonl(cksumtypes[i]);
    krb5_free_cksumtypes(kcontext, cksumtypes);
    if (status != 0) {
	if (checksum.length > 0)
	    krb5_free_checksum_contents(kcontext, &checksum);
	return status;
    }

    /* Allocate the preauth data structure. */
    send_pa = malloc(2 * sizeof(krb5_pa_data *));
    if (send_pa == NULL) {
	krb5_free_checksum_contents(kcontext, &checksum);
	return ENOMEM;
    }
    send_pa[1] = NULL;	/* Terminate list */
    send_pa[0] = malloc(sizeof(krb5_pa_data));
    if (send_pa[0] == NULL) {
	krb5_free_checksum_contents(kcontext, &checksum);
	free(send_pa);
	return ENOMEM;
    }
    send_pa[0]->pa_type = KRB5_PADATA_CKSUM_BODY_REQ;
    send_pa[0]->length = 4 + checksum.length;
    send_pa[0]->contents = malloc(4 + checksum.length);
    if (send_pa[0]->contents == NULL) {
	krb5_free_checksum_contents(kcontext, &checksum);
	free(send_pa[0]);
	free(send_pa);
	return ENOMEM;
    }

    /* Store the checksum. */
    memcpy(send_pa[0]->contents, &cksumtype, 4);
    memcpy(send_pa[0]->contents + 4, checksum.contents, checksum.length);
    *out_pa_data = send_pa;

    /* Clean up. */
    krb5_free_checksum_contents(kcontext, &checksum);

    return 0;
}

static krb5_error_code
client_gic_opt(krb5_context kcontext,
	       void *plugin_context,
	       krb5_get_init_creds_opt *opt,
	       const char *attr,
	       const char *value)
{
#ifdef DEBUG
    fprintf(stderr, "(cksum_body) client_gic_opt: received '%s' = '%s'\n",
	    attr, value); 
#endif
    return 0;
}

/* Initialize and tear down the server-side module, and do stat tracking. */
static krb5_error_code
server_init(krb5_context kcontext, void **module_context, const char **realmnames)
{
    struct server_stats *stats;
    stats = malloc(sizeof(struct server_stats));
    if (stats == NULL)
	return ENOMEM;
    stats->successes = 0;
    stats->failures = 0;
    *module_context = stats;
    return 0;
}
static void
server_fini(krb5_context kcontext, void *module_context)
{
    struct server_stats *stats;
    stats = module_context;
    if (stats != NULL) {
#ifdef DEBUG
	fprintf(stderr, "Total: %d clients failed, %d succeeded.\n",
		stats->failures, stats->successes);
#endif
	free(stats);
    }
}

/* Obtain and return any preauthentication data (which is destined for the
 * client) which matches type data->pa_type. */
static krb5_error_code
server_get_edata(krb5_context kcontext,
		 krb5_kdc_req *request,
		 struct _krb5_db_entry_new *client,
		 struct _krb5_db_entry_new *server,
		 preauth_get_entry_data_proc server_get_entry_data,
		 void *pa_module_context,
		 krb5_pa_data *data)
{
    krb5_data *key_data;
    krb5_keyblock *keys, *key;
    krb5_int32 *enctypes, enctype;
    int i;

    /* Retrieve the client's keys. */
    key_data = NULL;
    if ((*server_get_entry_data)(kcontext, request, client,
				 krb5plugin_preauth_keys, &key_data) != 0) {
#ifdef DEBUG
	fprintf(stderr, "Error retrieving client keys.\n");
#endif
	return KRB5KDC_ERR_PADATA_TYPE_NOSUPP;
    }

    /* Count which types of keys we've got, freeing the contents, which we
     * don't need at this point. */
    keys = (krb5_keyblock *) key_data->data;
    key = NULL;
    for (i = 0; keys[i].enctype != 0; i++)
	krb5_free_keyblock_contents(kcontext, &keys[i]);

    /* Return the list of encryption types. */
    enctypes = malloc((unsigned)i * 4);
    if (enctypes == NULL) {
	krb5_free_data(kcontext, key_data);
	return ENOMEM;
    }
#ifdef DEBUG
    fprintf(stderr, "Supported enctypes = {");
#endif
    for (i = 0; keys[i].enctype != 0; i++) {
#ifdef DEBUG
	fprintf(stderr, "%s%d", (i > 0) ? ", " : "", keys[i].enctype);
#endif
	enctype = htonl(keys[i].enctype);
	memcpy(&enctypes[i], &enctype, 4);
    }
#ifdef DEBUG
    fprintf(stderr, "}.\n");
#endif
    data->pa_type = KRB5_PADATA_CKSUM_BODY_REQ;
    data->length = (i * 4);
    data->contents = (unsigned char *) enctypes;
    krb5_free_data(kcontext, key_data);
    return 0;
}

/* Verify a request from a client. */
static krb5_error_code
server_verify(krb5_context kcontext,
	      struct _krb5_db_entry_new *client,
	      krb5_data *req_pkt,
	      krb5_kdc_req *request,
	      krb5_enc_tkt_part *enc_tkt_reply,
	      krb5_pa_data *data,
	      preauth_get_entry_data_proc server_get_entry_data,
	      void *pa_module_context,
	      void **pa_request_context,
	      krb5_data **e_data,
	      krb5_authdata ***authz_data)
{
    krb5_int32 cksumtype;
    krb5_checksum checksum;
    krb5_boolean valid;
    krb5_data *key_data, *req_body;
    krb5_keyblock *keys, *key;
    size_t length;
    int i;
    unsigned int j, cksumtypes_count;
    krb5_cksumtype *cksumtypes;
    krb5_error_code status;
    struct server_stats *stats;
    krb5_data *test_edata;
    test_svr_req_ctx *svr_req_ctx;
    krb5_authdata **my_authz_data = NULL;

    stats = pa_module_context;

#ifdef DEBUG
    fprintf(stderr, "cksum_body: server_verify\n");
#endif
    /* Verify the preauth data.  Start with the checksum type. */
    if (data->length < 4) {
	stats->failures++;
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    memcpy(&cksumtype, data->contents, 4);
    memset(&checksum, 0, sizeof(checksum));
    checksum.checksum_type = ntohl(cksumtype);

    /* Verify that the amount of data we have left is what we expect. */
    if (krb5_c_checksum_length(kcontext, checksum.checksum_type,
			       &length) != 0) {
#ifdef DEBUG
	fprintf(stderr, "Error determining checksum size (type = %d). "
		"Is it supported?\n", checksum.checksum_type);
#endif
	stats->failures++;
	return KRB5KDC_ERR_SUMTYPE_NOSUPP;
    }
    if (data->length - 4 != length) {
#ifdef DEBUG
	fprintf(stderr, "Checksum size doesn't match client packet size.\n");
#endif
	stats->failures++;
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }
    checksum.length = length;

    /* Pull up the client's keys. */
    key_data = NULL;
    if ((*server_get_entry_data)(kcontext, request, client,
				 krb5plugin_preauth_keys, &key_data) != 0) {
#ifdef DEBUG
	fprintf(stderr, "Error retrieving client keys.\n");
#endif
	stats->failures++;
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /* Find the key which would have been used to generate the checksum. */
    keys = (krb5_keyblock *) key_data->data;
    key = NULL;
    for (i = 0; keys[i].enctype != 0; i++) {
	key = &keys[i];
	cksumtypes_count = 0;
	cksumtypes = NULL;
	if (krb5_c_keyed_checksum_types(kcontext, key->enctype,
					&cksumtypes_count, &cksumtypes) != 0)
	    continue;
	for (j = 0; j < cksumtypes_count; j++) {
	    if (cksumtypes[j] == checksum.checksum_type)
		break;
	}
	if (cksumtypes != NULL)
	    krb5_free_cksumtypes(kcontext, cksumtypes);
	if (j < cksumtypes_count) {
#ifdef DEBUG
	    fprintf(stderr, "Found checksum key.\n");
#endif
	    break;
	}
    }
    if ((key == NULL) || (key->enctype == 0)) {
	for (i = 0; keys[i].enctype != 0; i++)
	    krb5_free_keyblock_contents(kcontext, &keys[i]);
	krb5_free_data(kcontext, key_data);
	stats->failures++;
	return KRB5KDC_ERR_SUMTYPE_NOSUPP;
    }

    /* Save a copy of the key. */
    if (krb5_copy_keyblock(kcontext, &keys[i], &key) != 0) {
	for (i = 0; keys[i].enctype != 0; i++)
	    krb5_free_keyblock_contents(kcontext, &keys[i]);
	krb5_free_data(kcontext, key_data);
	stats->failures++;
	return KRB5KDC_ERR_SUMTYPE_NOSUPP;
    }
    for (i = 0; keys[i].enctype != 0; i++)
	krb5_free_keyblock_contents(kcontext, &keys[i]);
    krb5_free_data(kcontext, key_data);

    /* Rebuild a copy of the client's request-body.  If we were serious
     * about doing this with any chance of working interoperability, we'd
     * extract the structure directly from the req_pkt structure.  This
     * will probably work if it's us on both ends, though. */
    req_body = NULL;
    if ((*server_get_entry_data)(kcontext, request, client,
				 krb5plugin_preauth_request_body,
				 &req_body) != 0) {
	krb5_free_keyblock(kcontext, key);
	stats->failures++;
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

#ifdef DEBUG
    fprintf(stderr, "AS key type %d, checksum type %d, %d bytes.\n",
	    key->enctype, checksum.checksum_type, req_body->length);
#endif

    /* Verify the checksum itself. */
    checksum.contents = data->contents + 4;
    valid = FALSE;
    status = krb5_c_verify_checksum(kcontext, key,
				    KRB5_KEYUSAGE_TGS_REQ_AUTH_CKSUM,
				    req_body, &checksum, &valid);

    /* Clean up. */
    krb5_free_data(kcontext, req_body);
    krb5_free_keyblock(kcontext, key);

    /* Evaluate our results. */
    if ((status != 0) || (!valid)) {
#ifdef DEBUG
	if (status != 0) {
	    fprintf(stderr, "Error in checksum verification.\n");
	} else {
	    fprintf(stderr, "Checksum mismatch.\n");
	}
#endif
	/* Return edata to exercise code that handles edata... */
	test_edata = malloc(sizeof(*test_edata));
	if (test_edata != NULL) {
	    test_edata->data = malloc(20);
	    if (test_edata->data == NULL) {
		free(test_edata);
	    } else {
		test_edata->length = 20;
		memset(test_edata->data, 'F', 20); /* fill it with junk */
		*e_data = test_edata;
	    }
	}
	stats->failures++;
	return KRB5KDC_ERR_PREAUTH_FAILED;
    }

    /*
     * Return some junk authorization data just to exercise the
     * code path handling the returned authorization data.
     *
     * NOTE that this is NOT VALID authorization data!
     */
#ifdef DEBUG
    fprintf(stderr, "cksum_body: doing authorization data!\n");
#endif
#if 1 /* USE_5000_AD */
#define AD_ALLOC_SIZE 5000
    /* ad_header consists of a sequence tag (0x30) and length (0x82 0x1384)
     * followed by octet string tag (0x04) and length (0x82 0x1380) */
    krb5_octet ad_header[] = {0x30, 0x82, 0x13, 0x84, 0x04, 0x82, 0x13, 0x80};
#else
#define AD_ALLOC_SIZE 100
    /* ad_header consists of a sequence tag (0x30) and length (0x62)
     * followed by octet string tag (0x04) and length (0x60) */
    krb5_octet ad_header[] = {0x30, 0x62, 0x04, 0x60};
#endif
    my_authz_data = malloc(2 * sizeof(*my_authz_data));
    if (my_authz_data != NULL) {
	my_authz_data[1] = NULL;
	my_authz_data[0] = malloc(sizeof(krb5_authdata));
	if (my_authz_data[0] == NULL) {
	    free(my_authz_data);
	    return ENOMEM;
	}
	my_authz_data[0]->contents = malloc(AD_ALLOC_SIZE);
	if (my_authz_data[0]->contents == NULL) {
	    free(my_authz_data[0]);
	    free(my_authz_data);
	    return ENOMEM;
	}
	memset(my_authz_data[0]->contents, '\0', AD_ALLOC_SIZE);
	my_authz_data[0]->magic = KV5M_AUTHDATA;
	my_authz_data[0]->ad_type = 1;
	my_authz_data[0]->length = AD_ALLOC_SIZE;
	memcpy(my_authz_data[0]->contents, ad_header, sizeof(ad_header));
	snprintf(my_authz_data[0]->contents + sizeof(ad_header),
		 AD_ALLOC_SIZE - sizeof(ad_header),
		 "cksum authorization data: %d bytes worth!\n", AD_ALLOC_SIZE);
	*authz_data = my_authz_data;
#ifdef DEBUG
	fprintf(stderr, "Returning %d bytes of authorization data\n",
		AD_ALLOC_SIZE);
#endif
    }

    /* Return edata to exercise code that handles edata... */
    test_edata = malloc(sizeof(*test_edata));
    if (test_edata != NULL) {
	test_edata->data = malloc(20);
	if (test_edata->data == NULL) {
	    free(test_edata);
	} else {
	    test_edata->length = 20;
	    memset(test_edata->data, 'S', 20); /* fill it with junk */
	    *e_data = test_edata;
	}
    }

    /* Return a request context to exercise code that handles it */
    svr_req_ctx = malloc(sizeof(*svr_req_ctx));
    if (svr_req_ctx != NULL) {
	svr_req_ctx->value1 = 111111;
	svr_req_ctx->value2 = 222222;
#ifdef DEBUG
	fprintf(stderr, "server_verify: returning context at %p\n",
		svr_req_ctx);
#endif
    }
    *pa_request_context = svr_req_ctx;

    /* Note that preauthentication succeeded. */
    enc_tkt_reply->flags |= TKT_FLG_PRE_AUTH;
    stats->successes++;
    return 0;
}

/* Create the response for a client. */
static krb5_error_code
server_return(krb5_context kcontext,
	      krb5_pa_data *padata,
	      struct _krb5_db_entry_new *client,
	      krb5_data *req_pkt,
	      krb5_kdc_req *request,
	      krb5_kdc_rep *reply,
	      struct _krb5_key_data *client_key,
	      krb5_keyblock *encrypting_key,
	      krb5_pa_data **send_pa,
	      preauth_get_entry_data_proc server_get_entry_data,
	      void *pa_module_context,
	      void **pa_request_context)
{
    /* We don't need to send data back on the return trip. */
    *send_pa = NULL;
    return 0;
}

/* Test server request context freeing */
static krb5_error_code
server_free_reqctx(krb5_context kcontext,
		   void *pa_module_context,
		   void **pa_request_context)
{
    test_svr_req_ctx *svr_req_ctx;
#ifdef DEBUG
    fprintf(stderr, "server_free_reqctx: entered!\n");
#endif
    if (pa_request_context == NULL)
	return 0;

    svr_req_ctx = *pa_request_context;
    if (svr_req_ctx == NULL)
	return 0;

    if (svr_req_ctx->value1 != 111111 || svr_req_ctx->value2 != 222222) {
	fprintf(stderr, "server_free_reqctx: got invalid req context "
		"at %p with values %d and %d\n",
		svr_req_ctx, svr_req_ctx->value1, svr_req_ctx->value2);
	return EINVAL;
    }
#ifdef DEBUG
    fprintf(stderr, "server_free_reqctx: freeing context at %p\n", svr_req_ctx);
#endif
    free(svr_req_ctx);
    *pa_request_context = NULL;
    return 0;
}

static int
server_get_flags(krb5_context kcontext, krb5_preauthtype pa_type)
{
    return PA_SUFFICIENT;
}

static krb5_preauthtype supported_client_pa_types[] = {
    KRB5_PADATA_CKSUM_BODY_REQ, 0,
};
static krb5_preauthtype supported_server_pa_types[] = {
    KRB5_PADATA_CKSUM_BODY_REQ, 0,
};

struct krb5plugin_preauth_client_ftable_v1 preauthentication_client_1 = {
    "cksum_body",			    /* name */
    &supported_client_pa_types[0],	    /* pa_type_list */
    NULL,				    /* enctype_list */
    NULL,				    /* plugin init function */
    NULL,				    /* plugin fini function */
    client_get_flags,			    /* get flags function */
    NULL,				    /* request init function */
    NULL,				    /* request fini function */
    client_process,			    /* process function */
    NULL,				    /* try_again function */
    client_gic_opt			    /* get init creds opt function */
};

struct krb5plugin_preauth_server_ftable_v1 preauthentication_server_1 = {
    "cksum_body",
    &supported_server_pa_types[0],
    server_init,
    server_fini,
    server_get_flags,
    server_get_edata,
    server_verify,
    server_return,
    server_free_reqctx
};

/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright 2015 Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "common.h"


/*
 * Test program for inquiring about a security context, intented to be run from
 * a Python test script.  Partially establishes a context to test inquiring
 * about an incomplete context, and then establishes full contexts and inquires
 * them.  Exits with status 0 if all operations are successful, or 1 if not.
 *
 * Usage: ./t_inq_ctx target_name
 */

static void
check_inq_context(const char *header, gss_ctx_id_t context,
                      int incomplete, OM_uint32 expected_flags,
                      int expected_locally_init)
{
    OM_uint32 major, minor;
    gss_name_t out_init_name, out_accept_name;
    OM_uint32 out_lifetime;
    gss_OID out_mech_type;
    OM_uint32 out_flags;
    int out_locally_init;
    int out_open;
    int mech_is_member;

    major = gss_inquire_context(&minor, context, &out_init_name,
                                &out_accept_name, &out_lifetime,
                                &out_mech_type, &out_flags, &out_locally_init,
                                &out_open);
    check_gsserr("gss_inquire_context", major, minor);

    major = gss_test_oid_set_member(&minor, out_mech_type, &mechset_krb5,
                                    &mech_is_member);
    check_gsserr("gss_test_oid_set_member", major, minor);

    assert(out_flags & expected_flags);
    assert(mech_is_member);
    assert(out_locally_init == expected_locally_init);
    if (incomplete) {
        assert(!out_open);
        assert(out_lifetime == 0);
        assert(out_init_name == GSS_C_NO_NAME);
        assert(out_accept_name == GSS_C_NO_NAME);
    } else {
        assert(out_open);
        assert(out_lifetime > 0);
        assert(out_init_name != GSS_C_NO_NAME);
        assert(out_accept_name != GSS_C_NO_NAME);
    }

    (void)gss_release_name(&minor, &out_accept_name);
    (void)gss_release_name(&minor, &out_init_name);
}

/* Call gss_init_sec_context() once to create an initiator context (which will
 * be partial if flags includes GSS_C_MUTUAL_FLAG and the mech is krb5). */
static void
start_init_context(gss_OID mech, gss_cred_id_t cred, gss_name_t tname,
                   OM_uint32 flags, gss_ctx_id_t *ctx)
{
    OM_uint32 major, minor;
    gss_buffer_desc itok = GSS_C_EMPTY_BUFFER;

    *ctx = GSS_C_NO_CONTEXT;
    major = gss_init_sec_context(&minor, cred, ctx, tname, mech, flags,
                                 GSS_C_INDEFINITE, GSS_C_NO_CHANNEL_BINDINGS,
                                 NULL, NULL, &itok, NULL, NULL);
    check_gsserr("gss_init_sec_context", major, minor);
    (void)gss_release_buffer(&minor, &itok);
}

int
main(int argc, char *argv[])
{
    OM_uint32 minor, flags;
    gss_name_t tname;
    gss_ctx_id_t ictx, actx;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s targetname\n", argv[0]);
        return 1;
    }
    tname = import_name(argv[1]);

    flags = GSS_C_SEQUENCE_FLAG | GSS_C_MUTUAL_FLAG;
    start_init_context(&mech_krb5, GSS_C_NO_CREDENTIAL, tname, flags, &ictx);
    check_inq_context("Partial initiator", ictx, 1, flags, 1);
    (void)gss_delete_sec_context(&minor, &ictx, NULL);

    establish_contexts(&mech_krb5, GSS_C_NO_CREDENTIAL, GSS_C_NO_CREDENTIAL,
                       tname, flags, &ictx, &actx, NULL, NULL, NULL);

    check_inq_context("Complete initiator", ictx, 0, flags, 1);
    check_inq_context("Complete acceptor", actx, 0, flags, 0);

    (void)gss_delete_sec_context(&minor, &ictx, NULL);
    (void)gss_delete_sec_context(&minor, &actx, NULL);

    (void)gss_release_name(&minor, &tname);
    return 0;
}

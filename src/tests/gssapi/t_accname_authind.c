/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* src/tests/gssapi/t_accname_authind.c - t_authind.py helper */
/*
 * Copyright (C) 2016 by the Massachusetts Institute of Technology.
 * Copyright (C) 2016 by Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include "common.h"

int
main(int argc, char *argv[])
{
    OM_uint32 minor, major, flags;
    gss_cred_id_t acceptor_cred;
    gss_name_t target_name, acceptor_name = GSS_C_NO_NAME, real_acceptor_name;
    gss_name_t src_name = GSS_C_NO_NAME;
    gss_buffer_desc namebuf;
    gss_ctx_id_t initiator_context, acceptor_context;

    if (argc < 1 || argc > 2) {
        fprintf(stderr, "Usage: %s targetname\n", argv[0]);
        return 1;
    }

    /* Import target. */
    target_name = import_name(argv[1]);

    /* Get acceptor cred. */
    major = gss_acquire_cred(&minor, acceptor_name, GSS_C_INDEFINITE,
                             GSS_C_NO_OID_SET, GSS_C_ACCEPT,
                             &acceptor_cred, NULL, NULL);
    check_gsserr("gss_acquire_cred", major, minor);

    flags = GSS_C_REPLAY_FLAG | GSS_C_SEQUENCE_FLAG;
    establish_contexts(&mech_krb5, GSS_C_NO_CREDENTIAL, acceptor_cred,
                       target_name, flags, &initiator_context,
                       &acceptor_context, &src_name, NULL, NULL);

    major = gss_inquire_context(&minor, acceptor_context, NULL,
                                &real_acceptor_name, NULL, NULL, NULL, NULL,
                                NULL);
    check_gsserr("gss_inquire_context", major, minor);

    namebuf.value = NULL;
    namebuf.length = 0;
    major = gss_display_name(&minor, src_name, &namebuf, NULL);
    check_gsserr("gss_display_name", major, minor);

    printf("%.*s\n", (int)namebuf.length, (char *)namebuf.value);
    enumerate_attributes(src_name, 1);

    (void)gss_release_name(&minor, &target_name);
    (void)gss_release_name(&minor, &acceptor_name);
    (void)gss_release_name(&minor, &real_acceptor_name);
    (void)gss_release_name(&minor, &src_name);
    (void)gss_release_cred(&minor, &acceptor_cred);
    (void)gss_delete_sec_context(&minor, &initiator_context, NULL);
    (void)gss_delete_sec_context(&minor, &acceptor_context, NULL);
    (void)gss_release_buffer(&minor, &namebuf);
    return 0;
}

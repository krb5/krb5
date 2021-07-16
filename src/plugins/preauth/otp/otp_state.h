/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/otp/otp_state.h - Internal declarations for OTP module */
/*
 * Copyright 2013 Red Hat, Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
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

#ifndef OTP_H_
#define OTP_H_

#include <k5-int.h>
#include <verto.h>

#include <com_err.h>

typedef enum otp_response {
    otp_response_fail = 0,
    otp_response_success
    /* Other values reserved for responses like next token or new pin. */
} otp_response;

/* Opaque to main.c, visible to otp_state.c */
typedef struct otp_state_st otp_state;
typedef struct token_st token;

/* Opaque to otp_state.c, visible to main.c */
struct verify_state;

krb5_error_code
otp_state_new(krb5_context ctx, otp_state **self);

void
otp_state_free(otp_state *self);

krb5_error_code
otp_state_parse_config(otp_state *state, const char *config_str,
                       krb5_const_principal princ, token **config_out);

void
otp_state_free_config(token *config);

/* On success and some failures, takes ownership of *config and *vstate and
 * sets them to NULL.  Asynchronously calls otp_verify_done() when complete. */
void
otp_state_verify(otp_state *state, verto_ctx *ctx,
                 const krb5_pa_otp_req *request, token **config,
                 struct verify_state **vstate);

/* Provided by main.c.  Must free vstate. */
void
otp_verify_done(krb5_error_code retval, struct verify_state *vstate,
                otp_response response, char *const *indicators);

#endif /* OTP_H_ */

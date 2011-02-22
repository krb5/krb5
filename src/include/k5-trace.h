/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * include/k5-trace.h
 *
 * Copyright (C) 2010 by the Massachusetts Institute of Technology.
 * All rights reserved.
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
 *
 * This header contains trace macro definitions, which map trace points within
 * the code to krb5int_trace() calls with descriptive text strings.
 *
 * Trace logging is intended to aid power users in diagnosing configuration
 * problems by showing what's going on behind the scenes of complex operations.
 * Although trace logging is sometimes useful to developers, it is not intended
 * as a replacement for a debugger, and it is not desirable to drown the user
 * in output.  Observe the following guidelines when adding trace points:
 *
 *   - Avoid mentioning function or variable names in messages.
 * 
 *   - Try to convey what decisions are being made and what external inputs
 *     they are based on, not the process of making decisions.
 *
 *   - It is generally not necessary to trace before returning an unrecoverable
 *     error.  If an error code is unclear by itself, make it clearer with
 *     krb5_set_error_message().
 *
 *   - Keep macros simple.  Add format specifiers to krb5int_trace's formatter
 *     as necessary (and document them here) instead of transforming macro
 *     arguments.
 *
 *   - Like printf, the trace formatter interface is not type-safe.  Check your
 *     formats carefully.  Cast integral arguments to the appropriate type if
 *     they do not already patch.
 *
 * The following specifiers are supported by the formatter (see the
 * implementation in lib/krb5/os/trace.c for details):
 *
 *   {int}         int, in decimal
 *   {long}        long, in decimal
 *   {str}         const char *, display as C string
 *   {lenstr}      size_t and const char *, as a counted string
 *   {hexlenstr}   size_t and const char *, as hex bytes
 *   {hashlenstr}  size_t and const char *, as four-character hex hash
 *   {addrinfo}    struct addrinfo *, show socket type, address, port
 *   {data}        krb5_data *, display as counted string
 *   {hexdata}     krb5_data *, display as hex bytes
 *   {errno}       int, display as number/errorstring
 *   {kerr}        krb5_error_code, display as number/errorstring
 *   {keyblock}    const krb5_keyblock *, display enctype and hash of key
 *   {key}         krb5_key, display enctype and hash of key
 *   {cksum}       const krb5_checksum *, display cksumtype and hex checksum
 *   {princ}       krb5_principal, unparse and display
 *   {patypes}     krb5_pa_data **, display list of padata type numbers
 *   {etype}       krb5_enctype, display shortest name of enctype
 *   {etypes}      krb5_enctype *, display list of enctypes
 *   {ccache}      krb5_ccache, display type:name
 *   {creds}       krb5_creds *, display clientprinc -> serverprinc
 */

#ifndef K5_TRACE_H
#define K5_TRACE_H

#if defined(DISABLE_TRACING)
#define TRACE(ctx, args)
#elif defined(_KRB5_INT_H)
#define TRACE(ctx, args) \
    do { if (ctx->trace_callback != NULL) krb5int_trace args; } while (0)
#else
/* This source file isn't using k5-int.h and doesn't know the internals of the
 * context structure, so don't try to optimize away the call. */
#define TRACE(ctx, args) krb5int_trace args
#endif

#define TRACE_CC_DESTROY(c, cache) \
    TRACE(c, (c, "Destroying ccache {ccache}", cache))
#define TRACE_CC_GEN_NEW(c, cache) \
    TRACE(c, (c, "Generating new unique ccache based on {ccache}", cache))
#define TRACE_CC_GET_CONFIG(c, cache, princ, key, data) \
    TRACE(c, (c, "Read config in {ccache} for {princ}: {str}: {data}", \
              cache, princ, key, data))
#define TRACE_CC_INIT(c, cache, princ) \
    TRACE(c, (c, "Initializing {ccache} with default princ {princ}", \
              cache, princ))
#define TRACE_CC_MOVE(c, src, dst) \
    TRACE(c, (c, "Moving contents of ccache {src} to {dst}", src, dst))
#define TRACE_CC_NEW_UNIQUE(c, type) \
    TRACE(c, (c, "Resolving unique ccache of type {str}", type))
#define TRACE_CC_REMOVE(c, cache, creds) \
    TRACE(c, (c, "Removing {creds} from {ccache}", creds, cache))
#define TRACE_CC_RETRIEVE(c, cache, creds, ret) \
    TRACE(c, (c, "Retrieving {creds} from {ccache} with result: {kerr}", \
              creds, cache, ret))
#define TRACE_CC_RETRIEVE_REF(c, cache, creds, ret) \
    TRACE(c, (c, "Retrying {creds} with result: {kerr}", creds, ret))
#define TRACE_CC_SET_CONFIG(c, cache, princ, key, data) \
    TRACE(c, (c, "Storing config in {ccache} for {princ}: {str}: {data}", \
              cache, princ, key, data))
#define TRACE_CC_STORE(c, cache, creds) \
    TRACE(c, (c, "Storing {creds} in {ccache}", creds, cache))
#define TRACE_CC_STORE_TKT(c, cache, creds) \
    TRACE(c, (c, "Also storing {creds} based on ticket", creds))

#define TRACE_FAST_ARMOR_CCACHE(c, ccache_name) \
    TRACE(c, (c, "FAST armor ccache: {str}", ccache_name))
#define TRACE_FAST_ARMOR_CCACHE_KEY(c, keyblock) \
    TRACE(c, (c, "Armor ccache sesion key: {keyblock}", keyblock))
#define TRACE_FAST_ARMOR_KEY(c, keyblock) \
    TRACE(c, (c, "FAST armor key: {keyblock}", keyblock))
#define TRACE_FAST_CCACHE_CONFIG(c) \
    TRACE(c, (c, "Using FAST due to armor ccache negotiation result"))
#define TRACE_FAST_DECODE(c) \
    TRACE(c, (c, "Decoding FAST response"))
#define TRACE_FAST_ENCODE(c) \
    TRACE(c, (c, "Encoding request body and padata into FAST request"))
#define TRACE_FAST_NEGO(c, avail) \
    TRACE(c, (c, "FAST negotiation: {str}available", (avail) ? "" : "un"))
#define TRACE_FAST_PADATA_UPGRADE(c) \
    TRACE(c, (c, "Upgrading to FAST due to presence of PA_FX_FAST in reply"))
#define TRACE_FAST_REPLY_KEY(c, keyblock) \
    TRACE(c, (c, "FAST reply key: {keyblock}", keyblock))
#define TRACE_FAST_REQUIRED(c) \
    TRACE(c, (c, "Using FAST due to KRB5_FAST_REQUIRED flag"))

#define TRACE_GIC_PWD_CHANGED(c) \
    TRACE(c, (c, "Getting initial TGT with changed password"))
#define TRACE_GIC_PWD_CHANGEPW(c, tries) \
    TRACE(c, (c, "Attempting password change; {int} tries remaining", tries))
#define TRACE_GIC_PWD_EXPIRED(c) \
    TRACE(c, (c, "Principal expired; getting changepw ticket"))
#define TRACE_GIC_PWD_MASTER(c) \
    TRACE(c, (c, "Retrying AS request with master KDC"))

#define TRACE_INIT_CREDS(c, princ) \
    TRACE(c, (c, "Getting initial credentials for {princ}", princ))
#define TRACE_INIT_CREDS_AS_KEY_GAK(c, keyblock) \
    TRACE(c, (c, "AS key obtained from gak_fct: {keyblock}", keyblock))
#define TRACE_INIT_CREDS_AS_KEY_PREAUTH(c, keyblock) \
    TRACE(c, (c, "AS key determined by preauth: {keyblock}", keyblock))
#define TRACE_INIT_CREDS_DECRYPTED_REPLY(c, keyblock) \
    TRACE(c, (c, "Decrypted AS reply; session key is: {keyblock}", keyblock))
#define TRACE_INIT_CREDS_ERROR_REPLY(c, code) \
    TRACE(c, (c, "Received error from KDC: {kerr}", code))
#define TRACE_INIT_CREDS_GAK(c, salt, s2kparams) \
    TRACE(c, (c, "Getting AS key, salt \"{data}\", params \"{data}\"", \
              salt, s2kparams))
#define TRACE_INIT_CREDS_PREAUTH_DECRYPT_FAIL(c, code) \
    TRACE(c, (c, "Decrypt with preauth AS key failed: {kerr}", code))
#define TRACE_INIT_CREDS_RESTART_FAST(c) \
    TRACE(c, (c, "Restarting to upgrade to FAST"))
#define TRACE_INIT_CREDS_RESTART_PREAUTH_FAILED(c) \
    TRACE(c, (c, "Restarting due to PREAUTH_FAILED from FAST negotiation"))
#define TRACE_INIT_CREDS_REFERRAL(c, realm) \
    TRACE(c, (c, "Following referral to realm {data}", realm))
#define TRACE_INIT_CREDS_RETRY_TCP(c) \
    TRACE(c, (c, "Request or response is too big for UDP; retrying with TCP"))
#define TRACE_INIT_CREDS_SALT_PRINC(c, salt) \
    TRACE(c, (c, "Salt derived from principal: {data}", salt))
#define TRACE_INIT_CREDS_SERVICE(c, service) \
    TRACE(c, (c, "Setting initial creds service to {string}", service))

#define TRACE_KT_GET_ENTRY(c, keytab, princ, vno, enctype, err) \
    TRACE(c, (c, "Retrieving {princ} from {keytab} (vno {int}, " \
              "enctype {etype}) with result: {kerr}", princ, keytab, \
              (int) vno, enctype, err))

#define TRACE_MK_REP(c, ctime, cusec, subkey, seqnum) \
    TRACE(c, (c, "Creating AP-REP, time {long}.{int}, subkey {keyblock}, " \
              "seqnum {int}", (long) ctime, (int) cusec, subkey, (int) seqnum))

#define TRACE_MK_REQ(c, creds, seqnum, subkey, sesskeyblock) \
    TRACE(c, (c, "Creating authenticator for {creds}, seqnum {int}, " \
              "subkey {key}, session key {keyblock}", creds, (int) seqnum, \
              subkey, sesskeyblock))
#define TRACE_MK_REQ_ETYPES(c, etypes) \
    TRACE(c, (c, "Negotiating for enctypes in authenticator: {etypes}", \
              etypes))

#define TRACE_MSPAC_VERIFY_FAIL(c, err) \
    TRACE(c, (c, "PAC checksum verification failed: {kerr}", err))
#define TRACE_MSPAC_DISCARD_UNVERF(c) \
    TRACE(c, (c, "Filtering out unverified MS PAC"))

#define TRACE_PREAUTH_COOKIE(c, len, data) \
    TRACE(c, (c, "Received cookie: {lenstr}", (size_t) len, data))
#define TRACE_PREAUTH_ENC_TS_KEY_GAK(c, keyblock) \
    TRACE(c, (c, "AS key obtained for encrypted timestamp: {keyblock}", \
              keyblock))
#define TRACE_PREAUTH_ENC_TS(c, sec, usec, plain, enc) \
    TRACE(c, (c, "Encrypted timestamp (for {long}.{int}): plain {hexdata}, " \
              "encrypted {hexdata}", (long) sec, (int) usec, plain, enc))
#define TRACE_PREAUTH_ETYPE_INFO(c, etype, salt, s2kparams) \
    TRACE(c, (c, "Selected etype info: etype {etype}, salt \"{data}\", " \
              "params \"{data}\"", etype, salt, s2kparams))
#define TRACE_PREAUTH_INFO_FAIL(c, patype, code) \
    TRACE(c, (c, "Preauth builtin info function failure, type={int}: {kerr}", \
              (int) patype, code))
#define TRACE_PREAUTH_INPUT(c, padata) \
    TRACE(c, (c, "Processing preauth types: {patypes}", padata))
#define TRACE_PREAUTH_OUTPUT(c, padata) \
    TRACE(c, (c, "Produced preauth for next request: {patypes}", padata))
#define TRACE_PREAUTH_PROCESS(c, name, patype, flags, code) \
    TRACE(c, (c, "Preauth module {str} ({int}) (flags={int}) returned: " \
              "{kerr}", name, (int) patype, flags, code))
#define TRACE_PREAUTH_SAM_KEY_GAK(c, keyblock) \
    TRACE(c, (c, "AS key obtained for SAM: {keyblock}", keyblock))
#define TRACE_PREAUTH_SALT(c, salt, patype) \
    TRACE(c, (c, "Received salt \"{str}\" via padata type {int}", salt, \
              (int) patype))
#define TRACE_PREAUTH_SKIP(c, name, patype) \
    TRACE(c, (c, "Skipping previously used preauth module {str} ({int})", \
              name, (int) patype))
#define TRACE_PREAUTH_TRYAGAIN_INPUT(c, padata) \
    TRACE(c, (c, "Preauth tryagain input types: {patypes}", padata))
#define TRACE_PREAUTH_TRYAGAIN_OUTPUT(c, padata) \
    TRACE(c, (c, "Followup preauth for next request: {patypes}", padata))

#define TRACE_RD_REP(c, ctime, cusec, subkey, seqnum) \
    TRACE(c, (c, "Read AP-REP, time {long}.{int}, subkey {keyblock}, " \
              "seqnum {int}", (long) ctime, (int) cusec, subkey, (int) seqnum))
#define TRACE_RD_REP_DCE(c, ctime, cusec, seqnum) \
    TRACE(c, (c, "Read DCE-style AP-REP, time {long}.{int}, seqnum {int}", \
              (long) ctime, (int) cusec, (int) seqnum))

#define TRACE_RD_REQ_DECRYPT_ANY(c, princ, keyblock)                \
    TRACE(c, (c, "Decrypted AP-REQ with server principal {princ}: " \
              "{keyblock}", princ, keyblock))
#define TRACE_RD_REQ_DECRYPT_SPECIFIC(c, princ, keyblock) \
    TRACE(c, (c, "Decrypted AP-REQ with specified server principal {princ}: " \
              "{keyblock}", princ, keyblock))
#define TRACE_RD_REQ_NEGOTIATED_ETYPE(c, etype) \
    TRACE(c, (c, "Negotiated enctype based on authenticator: {etype}", \
              etype))
#define TRACE_RD_REQ_SUBKEY(c, keyblock) \
    TRACE(c, (c, "Authenticator contains subkey: {keyblock}", keyblock))
#define TRACE_RD_REQ_TICKET(c, client, server, keyblock) \
    TRACE(c, (c, "AP-REQ ticket: {princ} -> {princ}, session key {keyblock}", \
              client, server, keyblock))

#define TRACE_SENDTO_KDC(c, len, rlm, master, tcp) \
    TRACE(c, (c, "Sending request ({int} bytes) to {data}{str}{str}", len, \
              rlm, (master) ? " (master)" : "", (tcp) ? " (tcp only)" : ""))
#define TRACE_SENDTO_KDC_MASTER(c, master) \
    TRACE(c, (c, "Response was{str} from master KDC", (master) ? "" : " not"))
#define TRACE_SENDTO_KDC_RESPONSE(c, addr) \
    TRACE(c, (c, "Received answer from {addrinfo}", addr))
#define TRACE_SENDTO_KDC_TCP_CONNECT(c, addr) \
    TRACE(c, (c, "Initiating TCP connection to {addrinfo}", addr))
#define TRACE_SENDTO_KDC_TCP_DISCONNECT(c, addr) \
    TRACE(c, (c, "Terminating TCP connection to {addrinfo}", addr))
#define TRACE_SENDTO_KDC_TCP_ERROR_CONNECT(c, addr, err) \
    TRACE(c, (c, "TCP error connecting to {addrinfo}: {errno}", addr, err))
#define TRACE_SENDTO_KDC_TCP_ERROR_RECV(c, addr, err) \
    TRACE(c, (c, "TCP error receiving from {addrinfo}: {errno}", addr, err))
#define TRACE_SENDTO_KDC_TCP_ERROR_RECV_LEN(c, addr, err) \
    TRACE(c, (c, "TCP error receiving from {addrinfo}: {errno}", addr, err))
#define TRACE_SENDTO_KDC_TCP_ERROR_SEND(c, addr, err) \
    TRACE(c, (c, "TCP error sending to {addrinfo}: {errno}", addr, err))
#define TRACE_SENDTO_KDC_TCP_SEND(c, addr) \
    TRACE(c, (c, "Sending TCP request to {addrinfo}", addr))
#define TRACE_SENDTO_KDC_UDP_ERROR_RECV(c, addr, err) \
    TRACE(c, (c, "UDP error receiving from {addrinfo}: {errno}", addr, err))
#define TRACE_SENDTO_KDC_UDP_ERROR_SEND_INITIAL(c, addr, err) \
    TRACE(c, (c, "UDP error sending to {addrinfo}: {errno}", addr, err))
#define TRACE_SENDTO_KDC_UDP_ERROR_SEND_RETRY(c, addr, err) \
    TRACE(c, (c, "UDP error sending to {addrinfo}: {errno}", addr, err))
#define TRACE_SENDTO_KDC_UDP_SEND_INITIAL(c, addr) \
    TRACE(c, (c, "Sending initial UDP request to {addrinfo}", addr))
#define TRACE_SENDTO_KDC_UDP_SEND_RETRY(c, addr) \
    TRACE(c, (c, "Sending retry UDP request to {addrinfo}", addr))

#define TRACE_SEND_TGS_ETYPES(c, etypes) \
    TRACE(c, (c, "etypes requested in TGS request: {etypes}", etypes))
#define TRACE_SEND_TGS_SUBKEY(c, keyblock) \
    TRACE(c, (c, "Generated subkey for TGS request: {keyblock}", keyblock))

#define TRACE_TGS_REPLY(c, client, server, keyblock) \
    TRACE(c, (c, "TGS reply is for {princ} -> {princ} with session key " \
              "{keyblock}", client, server, keyblock))
#define TRACE_TGS_REPLY_DECODE_SESSION(c, keyblock) \
    TRACE(c, (c, "TGS reply didn't decode with subkey; trying session key " \
              "({keyblock)}", keyblock))

#define TRACE_TKT_CREDS(c, creds, cache) \
    TRACE(c, (c, "Getting credentials {creds} using ccache {ccache}", \
              creds, cache))
#define TRACE_TKT_CREDS_ADVANCE(c, realm) \
    TRACE(c, (c, "Received TGT for {data}; advancing current realm", realm))
#define TRACE_TKT_CREDS_CACHED_INTERMEDIATE_TGT(c, tgt) \
    TRACE(c, (c, "Found cached TGT for intermediate realm: {creds}", tgt))
#define TRACE_TKT_CREDS_CACHED_SERVICE_TGT(c, tgt) \
    TRACE(c, (c, "Found cached TGT for service realm: {creds}", tgt))
#define TRACE_TKT_CREDS_CLOSER_REALM(c, realm) \
    TRACE(c, (c, "Trying next closer realm in path: {data}", realm))
#define TRACE_TKT_CREDS_COMPLETE(c, princ) \
    TRACE(c, (c, "Received creds for desired service {princ}", princ))
#define TRACE_TKT_CREDS_FALLBACK(c, realm) \
    TRACE(c, (c, "Local realm referral failed; trying fallback realm {data}", \
              realm))
#define TRACE_TKT_CREDS_LOCAL_TGT(c, tgt) \
    TRACE(c, (c, "Starting with TGT for client realm: {creds}", tgt))
#define TRACE_TKT_CREDS_NON_TGT(c, princ) \
    TRACE(c, (c, "Received non-TGT referral response ({princ}); trying " \
              "again without referrals", princ))
#define TRACE_TKT_CREDS_OFFPATH(c, realm) \
    TRACE(c, (c, "Received TGT for offpath realm {data}", realm))
#define TRACE_TKT_CREDS_REFERRAL(c, princ) \
    TRACE(c, (c, "Following referral TGT {princ}", princ))
#define TRACE_TKT_CREDS_REFERRAL_REALM(c, princ) \
    TRACE(c, (c, "Server has referral realm; starting with {princ}", princ))
#define TRACE_TKT_CREDS_RESPONSE_CODE(c, code) \
    TRACE(c, (c, "TGS request result: {kerr}", code))
#define TRACE_TKT_CREDS_RETRY_TCP(c) \
    TRACE(c, (c, "Request or response is too big for UDP; retrying with TCP"))
#define TRACE_TKT_CREDS_SERVICE_REQ(c, princ, referral) \
    TRACE(c, (c, "Requesting tickets for {princ}, referrals {str}", princ, \
              (referral) ? "on" : "off"))
#define TRACE_TKT_CREDS_TARGET_TGT(c, princ) \
    TRACE(c, (c, "Received TGT for service realm: {princ}", princ))
#define TRACE_TKT_CREDS_TARGET_TGT_OFFPATH(c, princ) \
    TRACE(c, (c, "Received TGT for service realm: {princ}", princ))
#define TRACE_TKT_CREDS_TGT_REQ(c, next, cur) \
    TRACE(c, (c, "Requesting TGT {princ} using TGT {princ}", next, cur))
#define TRACE_TKT_CREDS_WRONG_ENCTYPE(c) \
    TRACE(c, (c, "Retrying TGS request with desired service ticket enctypes"))

#endif /* K5_TRACE_H */

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

#include<windows.h>
#include<netidmgr.h>
#include<dynimport.h>
#include<krb5common.h>
#ifdef DEBUG
#include<assert.h>
#endif
#include<strsafe.h>

/**************************************/
/* khm_krb5_error():           */
/**************************************/
int 
khm_krb5_error(krb5_error_code rc, LPCSTR FailedFunctionName, 
                 int FreeContextFlag, krb5_context * ctx, 
                 krb5_ccache * cache)
{
#ifdef NO_KRB5
    return 0;
#else

#ifdef SHOW_MESSAGE_IN_AN_ANNOYING_WAY
    char message[256];
    const char *errText;
    int krb5Error = ((int)(rc & 255));  

    errText = perror_message(rc);   
    _snprintf(message, sizeof(message), 
        "%s\n(Kerberos error %ld)\n\n%s failed", 
        errText, 
        krb5Error, 
        FailedFunctionName);

    MessageBoxA(NULL, message, "Kerberos Five", MB_OK | MB_ICONERROR | 
        MB_TASKMODAL | 
        MB_SETFOREGROUND);
#endif

    if (FreeContextFlag == 1)
    {
        if (*ctx != NULL)
        {
            if (*cache != NULL) {
                pkrb5_cc_close(*ctx, *cache);
                *cache = NULL;
            }

            pkrb5_free_context(*ctx);
            *ctx = NULL;
        }
    }

    return rc;

#endif //!NO_KRB5
}

int 
khm_krb5_initialize(khm_handle ident, 
                    krb5_context *ctx, 
                    krb5_ccache *cache)
{
#ifdef NO_KRB5
    return(0);
#else

    LPCSTR          functionName = NULL;
    int             freeContextFlag = 0;
    krb5_error_code	rc = 0;
    krb5_flags          flags = 0;

    if (pkrb5_init_context == NULL)
        return 1;

    if (*ctx == 0 && (rc = (*pkrb5_init_context)(ctx))) {
        functionName = "krb5_init_context()";
        freeContextFlag = 0;
        goto on_error;
    }

    if(*cache == 0) {
        wchar_t wccname[MAX_PATH];
        khm_size cbwccname;

        if(ident != NULL) {
            cbwccname = sizeof(wccname);
            do {
                char ccname[256];

                if(KHM_FAILED(kcdb_identity_get_attrib(ident, L"Krb5CCName",
                                                       NULL, wccname,
                                                       &cbwccname))) {
                    cbwccname = sizeof(wccname);
                    if (KHM_FAILED
                        (khm_krb5_find_ccache_for_identity(ident,
                                                           ctx,
                                                           wccname,
                                                           &cbwccname))) {
#ifdef DEBUG_LIKE_A_MADMAN
                        assert(FALSE);
#endif
                        break;
                    }
                }

                if(UnicodeStrToAnsi(ccname, sizeof(ccname), wccname) == 0)
                    break;

                if((*pkrb5_cc_resolve)(*ctx, ccname, cache)) {
                    functionName = "krb5_cc_resolve()";
                    freeContextFlag = 1;
                    goto on_error;
                }
            } while(FALSE);
        }

#ifndef FAILOVER_TO_DEFAULT_CCACHE
	rc = 1;
#endif
        if (*cache == 0
#ifdef FAILOVER_TO_DEFAULT_CCACHE
            && (rc = (*pkrb5_cc_default)(*ctx, cache))
#endif
            ) {
            functionName = "krb5_cc_default()";
            freeContextFlag = 1;
            goto on_error;
        }
    }

#ifdef KRB5_TC_NOTICKET
    flags = KRB5_TC_NOTICKET;
#endif

    if ((rc = (*pkrb5_cc_set_flags)(*ctx, *cache, flags)))
    {
        if (rc != KRB5_FCC_NOFILE && rc != KRB5_CC_NOTFOUND)
            khm_krb5_error(rc, "krb5_cc_set_flags()", 0, ctx, 
            cache);
        else if ((rc == KRB5_FCC_NOFILE || rc == KRB5_CC_NOTFOUND) && *ctx != NULL) {
            if (*cache != NULL) {
                (*pkrb5_cc_close)(*ctx, *cache);
                *cache = NULL;
            }
        }
        return rc;
    }
    return 0;

on_error:
    return khm_krb5_error(rc, functionName, freeContextFlag, ctx, cache);
#endif //!NO_KRB5
}

#define TIMET_TOLERANCE (60*5)

khm_int32 KHMAPI
khm_get_identity_expiration_time(krb5_context ctx, krb5_ccache cc, 
                                 khm_handle ident, 
                                 krb5_timestamp * pexpiration)
{
    krb5_principal principal = 0;
    char * princ_name = NULL;
    krb5_creds creds;
    krb5_error_code code;
    krb5_error_code cc_code;
    krb5_cc_cursor cur;
    krb5_timestamp now, expiration = 0;

    wchar_t w_ident_name[KCDB_IDENT_MAXCCH_NAME];
    char    ident_name[KCDB_IDENT_MAXCCH_NAME];
    khm_size cb;

    khm_int32 rv = KHM_ERROR_NOT_FOUND;

    if (!ctx || !cc || !ident || !pexpiration)
        return KHM_ERROR_GENERAL;

    code = pkrb5_cc_get_principal(ctx, cc, &principal);

    if ( code )
        return KHM_ERROR_INVALID_PARAM;

    cb = sizeof(w_ident_name);
    kcdb_identity_get_name(ident, w_ident_name, &cb);
    UnicodeStrToAnsi(ident_name, sizeof(ident_name), w_ident_name);

    code = pkrb5_unparse_name(ctx, principal, &princ_name);

    /* compare principal to ident. */

    if ( code || !princ_name ||
         strcmp(princ_name, ident_name) ) {
        if (princ_name)
            pkrb5_free_unparsed_name(ctx, princ_name);
        pkrb5_free_principal(ctx, principal);
        return KHM_ERROR_UNKNOWN;
    }

    pkrb5_free_unparsed_name(ctx, princ_name);
    pkrb5_free_principal(ctx, principal);

    code = pkrb5_timeofday(ctx, &now);

    if (code)
        return KHM_ERROR_UNKNOWN;

    cc_code = pkrb5_cc_start_seq_get(ctx, cc, &cur);

    while (!(cc_code = pkrb5_cc_next_cred(ctx, cc, &cur, &creds))) {
        krb5_data * c0 = krb5_princ_name(ctx, creds.server);
        krb5_data * c1  = krb5_princ_component(ctx, creds.server, 1);
        krb5_data * r = krb5_princ_realm(ctx, creds.server);

        if ( c0 && c1 && r && c1->length == r->length && 
             !strncmp(c1->data,r->data,r->length) &&
             !strncmp("krbtgt",c0->data,c0->length) ) {

            /* we have a TGT, check for the expiration time.
             * if it is valid and renewable, use the renew time 
             */

            if (!(creds.ticket_flags & TKT_FLG_INVALID) &&
                creds.times.starttime < (now + TIMET_TOLERANCE) && 
                (creds.times.endtime + TIMET_TOLERANCE) > now) {
                expiration = creds.times.endtime;

                if ((creds.ticket_flags & TKT_FLG_RENEWABLE) && 
                    (creds.times.renew_till > creds.times.endtime)) {
                    expiration = creds.times.renew_till;
                }
            }
        }
    }

    if (cc_code == KRB5_CC_END) {
        cc_code = pkrb5_cc_end_seq_get(ctx, cc, &cur);
        rv = KHM_ERROR_SUCCESS;
        *pexpiration = expiration;
    }

    return rv;
}

khm_int32 KHMAPI
khm_krb5_find_ccache_for_identity(khm_handle ident, krb5_context *pctx,
                                  void * buffer, khm_size * pcbbuf)
{
    krb5_context        ctx = 0;
    krb5_ccache         cache = 0;
    krb5_error_code     code;
    apiCB *             cc_ctx = 0;
    struct _infoNC **   pNCi = NULL;
    int                 i;
    khm_int32           t;
    wchar_t *           ms = NULL;
    khm_size            cb;
    krb5_timestamp      expiration = 0;
    krb5_timestamp      best_match_expiration = 0;
    char                best_match_ccname[256] = "";
    khm_handle          csp_params = NULL;
    khm_handle          csp_plugins = NULL;

    if (!buffer || !pcbbuf)
    return KHM_ERROR_GENERAL;

    ctx = *pctx;

    if (!pcc_initialize ||
        !pcc_get_NC_info ||
        !pcc_free_NC_info ||
        !pcc_shutdown)
        goto _skip_cc_iter;

    code = pcc_initialize(&cc_ctx, CC_API_VER_2, NULL, NULL);
    if (code)
        goto _exit;

    code = pcc_get_NC_info(cc_ctx, &pNCi);

    if (code) 
        goto _exit;

    for(i=0; pNCi[i]; i++) {
        if (pNCi[i]->vers != CC_CRED_V5)
            continue;

        code = (*pkrb5_cc_resolve)(ctx, pNCi[i]->name, &cache);
        if (code)
            continue;

        /* need a function to check the cache for the identity
         * and determine if it has valid tickets.  If it has 
         * the right identity and valid tickets, store the 
         * expiration time and the cache name.  If it has the
         * right identity but no valid tickets, store the ccache
         * name and an expiration time of zero.  if it does not
         * have the right identity don't save the name.
         * 
         * Keep searching to find the best cache available.
         */

        if (KHM_SUCCEEDED(khm_get_identity_expiration_time(ctx, cache, 
                                                           ident, 
                                                           &expiration))) {
            if ( expiration > best_match_expiration ) {
                best_match_expiration = expiration;
                StringCbCopyA(best_match_ccname, 
                              sizeof(best_match_ccname),
                              "API:");
                StringCbCatA(best_match_ccname,
                             sizeof(best_match_ccname),
                             pNCi[i]->name);
                expiration = 0;
            }
        }

        if(ctx != NULL && cache != NULL)
            (*pkrb5_cc_close)(ctx, cache);
        cache = 0;
    }

 _skip_cc_iter:

    if (KHM_SUCCEEDED(kmm_get_plugins_config(0, &csp_plugins))) {
        khc_open_space(csp_plugins, L"Krb5Cred\\Parameters",  0, &csp_params);
        khc_close_space(csp_plugins);
        csp_plugins = NULL;
    }

#ifdef DEBUG
    if (csp_params == NULL) {
        assert(FALSE);
    }
#endif

    if (csp_params &&
        KHM_SUCCEEDED(khc_read_int32(csp_params, L"MsLsaList", &t)) && t) {
        code = (*pkrb5_cc_resolve)(ctx, "MSLSA:", &cache);
        if (code == 0 && cache) {
            if (KHM_SUCCEEDED(khm_get_identity_expiration_time(ctx, cache, 
                                                               ident, 
                                                               &expiration))) {
                if ( expiration > best_match_expiration ) {
                    best_match_expiration = expiration;
                    StringCbCopyA(best_match_ccname, sizeof(best_match_ccname),
                                  "MSLSA:");
                    expiration = 0;
                }
            }
        }

        if (ctx != NULL && cache != NULL)
            (*pkrb5_cc_close)(ctx, cache);

        cache = 0;
    }

    if (csp_params &&
        khc_read_multi_string(csp_params, L"FileCCList", NULL, &cb)
        == KHM_ERROR_TOO_LONG &&
        cb > sizeof(wchar_t) * 2) {

        wchar_t * t;
        char ccname[MAX_PATH + 6];

        ms = PMALLOC(cb);

#ifdef DEBUG
        assert(ms);
#endif

        khc_read_multi_string(csp_params, L"FileCCList", ms, &cb);
        for(t = ms; t && *t; t = multi_string_next(t)) {
            StringCchPrintfA(ccname, ARRAYLENGTH(ccname),
                             "FILE:%S", t);

            code = (*pkrb5_cc_resolve)(ctx, ccname, &cache);
            if (code)
                continue;

            if (KHM_SUCCEEDED(khm_get_identity_expiration_time(ctx, cache, 
                                                               ident, 
                                                               &expiration))) {
                if ( expiration > best_match_expiration ) {
                    best_match_expiration = expiration;
                    StringCbCopyA(best_match_ccname,
                                  sizeof(best_match_ccname),
                                  ccname);
                    expiration = 0;
                }
            }

            if (ctx != NULL && cache != NULL)
                (*pkrb5_cc_close)(ctx, cache);
            cache = 0;
        }

        PFREE(ms);
    }
 _exit:
    if (csp_params)
        khc_close_space(csp_params);

    if (pNCi)
        (*pcc_free_NC_info)(cc_ctx, &pNCi);

    if (cc_ctx)
        (*pcc_shutdown)(&cc_ctx);

    if (best_match_ccname[0]) {
        
        if (*pcbbuf = AnsiStrToUnicode((wchar_t *)buffer, 
                                       *pcbbuf,
                                       best_match_ccname)) {

            *pcbbuf = (*pcbbuf + 1) * sizeof(wchar_t);

            return KHM_ERROR_SUCCESS;
        }

    }

    return KHM_ERROR_GENERAL;
}

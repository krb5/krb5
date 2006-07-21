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

/* Originally this was krb5routines.c in Leash sources.  Subsequently
modified and adapted for NetIDMgr */

#include<krbcred.h>
#include<kherror.h>

#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>

#include <string.h>
#include <time.h>
#include <assert.h>
#include <strsafe.h>

long
khm_convert524(krb5_context alt_ctx)
{
    krb5_context ctx = 0;
    krb5_error_code code = 0;
    int icode = 0;
    krb5_principal me = 0;
    krb5_principal server = 0;
    krb5_creds *v5creds = 0;
    krb5_creds increds;
    krb5_ccache cc = 0;
    CREDENTIALS * v4creds = NULL;
    static int init_ets = 1;

    if (!pkrb5_init_context ||
        !pkrb_in_tkt ||
        !pkrb524_init_ets ||
        !pkrb524_convert_creds_kdc)
        return 0;

    v4creds = (CREDENTIALS *) PMALLOC(sizeof(CREDENTIALS));
    memset((char *) v4creds, 0, sizeof(CREDENTIALS));

    memset((char *) &increds, 0, sizeof(increds));
    /*
    From this point on, we can goto cleanup because increds is
    initialized.
    */

    if (alt_ctx)
    {
        ctx = alt_ctx;
    }
    else
    {
        code = pkrb5_init_context(&ctx);
        if (code) goto cleanup;
    }

    code = pkrb5_cc_default(ctx, &cc);
    if (code) goto cleanup;

    if ( init_ets ) {
        pkrb524_init_ets(ctx);
        init_ets = 0;
    }

    if (code = pkrb5_cc_get_principal(ctx, cc, &me))
        goto cleanup;

    if ((code = pkrb5_build_principal(ctx,
        &server,
        krb5_princ_realm(ctx, me)->length,
        krb5_princ_realm(ctx, me)->data,
        "krbtgt",
        krb5_princ_realm(ctx, me)->data,
        NULL))) 
    {
        goto cleanup;
    }

    increds.client = me;
    increds.server = server;
    increds.times.endtime = 0;
    increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    if ((code = pkrb5_get_credentials(ctx, 0,
        cc,
        &increds,
        &v5creds))) 
    {
        goto cleanup;
    }

    if ((icode = pkrb524_convert_creds_kdc(ctx,
        v5creds,
        v4creds))) 
    {
        goto cleanup;
    }

    /* initialize ticket cache */
    if ((icode = pkrb_in_tkt(v4creds->pname, v4creds->pinst, v4creds->realm)
        != KSUCCESS)) 
    {
        goto cleanup;
    }
    /* stash ticket, session key, etc. for future use */
    if ((icode = pkrb_save_credentials(v4creds->service,
        v4creds->instance,
        v4creds->realm,
        v4creds->session,
        v4creds->lifetime,
        v4creds->kvno,
        &(v4creds->ticket_st),
        v4creds->issue_date))) 
    {
        goto cleanup;
    }

cleanup:
    memset(v4creds, 0, sizeof(v4creds));
    PFREE(v4creds);

    if (v5creds) {
        pkrb5_free_creds(ctx, v5creds);
    }
    if (increds.client == me)
        me = 0;
    if (increds.server == server)
        server = 0;
    pkrb5_free_cred_contents(ctx, &increds);
    if (server) {
        pkrb5_free_principal(ctx, server);
    }
    if (me) {
        pkrb5_free_principal(ctx, me);
    }
    pkrb5_cc_close(ctx, cc);

    if (ctx && (ctx != alt_ctx)) {
        pkrb5_free_context(ctx);
    }
    return !(code || icode);
}

#ifdef DEPRECATED_REMOVABLE
int com_addr(void)
{
    long ipAddr;
    char loc_addr[ADDR_SZ];
    CREDENTIALS cred;    
    char service[40];
    char instance[40];
    //    char addr[40];
    char realm[40];
    struct in_addr LocAddr;
    int k_errno;

    if (pkrb_get_cred == NULL)
        return(KSUCCESS);

    k_errno = (*pkrb_get_cred)(service,instance,realm,&cred);
    if (k_errno)
        return KRBERR(k_errno);

    while(1) {
        ipAddr = (*pLocalHostAddr)();
        LocAddr.s_addr = ipAddr;
        StringCbCopyA(loc_addr, sizeof(loc_addr), inet_ntoa(LocAddr));
        if ( strcmp(cred.address, loc_addr) != 0) {
            /* TODO: do something about this */
            //Leash_kdestroy ();
            break;
        }
        break;
    } // while()
    return 0;
} 
#endif

#ifndef ENCTYPE_LOCAL_RC4_MD4
#define ENCTYPE_LOCAL_RC4_MD4    0xFFFFFF80
#endif

#define MAX_ADDRS 256

static long get_tickets_from_cache(krb5_context ctx, 
                                   krb5_ccache cache)
{
    krb5_error_code code;
    krb5_principal  KRBv5Principal;
    krb5_flags	    flags = 0;
    krb5_cc_cursor  KRBv5Cursor;
    krb5_creds	    KRBv5Credentials;
    krb5_ticket    *tkt=NULL;
    char	   *ClientName;
    char	   *PrincipalName;
    wchar_t         wbuf[256];  /* temporary conversion buffer */
    wchar_t         wcc_name[KRB5_MAXCCH_CCNAME]; /* credential cache name */
    char	   *sServerName;
    khm_handle      ident = NULL;
    khm_handle      cred = NULL;
    time_t          tt;
    FILETIME        ft, eft;
    khm_int32       ti;

#ifdef KRB5_TC_NOTICKET
    flags = KRB5_TC_NOTICKET;
#else
    flags = 0;
#endif

    {
        const char * cc_name;
        const char * cc_type;

        cc_name = (*pkrb5_cc_get_name)(ctx, cache);
        if(cc_name) {
            cc_type = (*pkrb5_cc_get_type)(ctx, cache);
            if (cc_type) {
                StringCbPrintf(wcc_name, sizeof(wcc_name), L"%S:%S", cc_type, cc_name);
            } else {
                AnsiStrToUnicode(wcc_name, sizeof(wcc_name), cc_name);
                khm_krb5_canon_cc_name(wcc_name, sizeof(wcc_name));
            }
        } else {
            cc_type = (*pkrb5_cc_get_type)(ctx, cache);
            if (cc_type) {
                StringCbPrintf(wcc_name, sizeof(wcc_name), L"%S:", cc_type);
            } else {
#ifdef DEBUG
                assert(FALSE);
#endif
                StringCbCopy(wcc_name, sizeof(wcc_name), L"");
            }
        }
    }

    if ((code = (*pkrb5_cc_set_flags)(ctx, cache, flags)))
    {
        if (code != KRB5_FCC_NOFILE && code != KRB5_CC_NOTFOUND)
            khm_krb5_error(code, "krb5_cc_set_flags()", 0, &ctx, &cache);

        goto _exit;
    }

    if ((code = (*pkrb5_cc_get_principal)(ctx, cache, &KRBv5Principal)))
    {
        if (code != KRB5_FCC_NOFILE && code != KRB5_CC_NOTFOUND)
            khm_krb5_error(code, "krb5_cc_get_principal()", 0, &ctx, &cache);

        goto _exit;
    }

    PrincipalName = NULL;
    ClientName = NULL;
    sServerName = NULL;
    if ((code = (*pkrb5_unparse_name)(ctx, KRBv5Principal, 
        (char **)&PrincipalName))) 
    {
        if (PrincipalName != NULL)
            (*pkrb5_free_unparsed_name)(ctx, PrincipalName);

        (*pkrb5_free_principal)(ctx, KRBv5Principal);

        goto _exit;
    }

    if (!strcspn(PrincipalName, "@" ))
    {
        if (PrincipalName != NULL)
            (*pkrb5_free_unparsed_name)(ctx, PrincipalName);

        (*pkrb5_free_principal)(ctx, KRBv5Principal);

        goto _exit;
    }

    AnsiStrToUnicode(wbuf, sizeof(wbuf), PrincipalName);
    if(KHM_FAILED(kcdb_identity_create(wbuf, KCDB_IDENT_FLAG_CREATE, 
                                       &ident))) {
        /* something bad happened */
        code = 1;
        goto _exit;
    }

    (*pkrb5_free_principal)(ctx, KRBv5Principal);

    if ((code = (*pkrb5_cc_start_seq_get)(ctx, cache, &KRBv5Cursor))) 
    {
        goto _exit; 
    }

    memset(&KRBv5Credentials, '\0', sizeof(KRBv5Credentials));

    ClientName = NULL;
    sServerName = NULL;
    cred = NULL;

    while (!(code = pkrb5_cc_next_cred(ctx, cache, &KRBv5Cursor, 
                                       &KRBv5Credentials))) 
    {
        khm_handle tident = NULL;
        khm_int32 cred_flags = 0;

        if(ClientName != NULL)
            (*pkrb5_free_unparsed_name)(ctx, ClientName);
        if(sServerName != NULL)
            (*pkrb5_free_unparsed_name)(ctx, sServerName);
        if(cred)
            kcdb_cred_release(cred);

        ClientName = NULL;
        sServerName = NULL;
        cred = NULL;

        if ((*pkrb5_unparse_name)(ctx, KRBv5Credentials.client, &ClientName))
        {
            (*pkrb5_free_cred_contents)(ctx, &KRBv5Credentials);
            khm_krb5_error(code, "krb5_free_cred_contents()", 0, &ctx, &cache);
            continue;
        }

        if ((*pkrb5_unparse_name)(ctx, KRBv5Credentials.server, &sServerName))
        {
            (*pkrb5_free_cred_contents)(ctx, &KRBv5Credentials);
            khm_krb5_error(code, "krb5_free_cred_contents()", 0, &ctx, &cache);
            continue;
        }

        /* if the ClientName differs from PrincipalName for some
           reason, we need to create a new identity */
        if(strcmp(ClientName, PrincipalName)) {
            AnsiStrToUnicode(wbuf, sizeof(wbuf), ClientName);
            if(KHM_FAILED(kcdb_identity_create(wbuf, KCDB_IDENT_FLAG_CREATE, 
                                               &tident))) {
                (*pkrb5_free_cred_contents)(ctx, &KRBv5Credentials);
                continue;
            }
        } else {
            tident = ident;
        }

        AnsiStrToUnicode(wbuf, sizeof(wbuf), sServerName);
        if(KHM_FAILED(kcdb_cred_create(wbuf, tident, credtype_id_krb5, 
                                       &cred))) {
            (*pkrb5_free_cred_contents)(ctx, &KRBv5Credentials);
            continue;
        }

        if (!KRBv5Credentials.times.starttime)
            KRBv5Credentials.times.starttime = KRBv5Credentials.times.authtime;

        tt = KRBv5Credentials.times.starttime;
        TimetToFileTime(tt, &ft);
        kcdb_cred_set_attr(cred, KCDB_ATTR_ISSUE, &ft, sizeof(ft));

        tt = KRBv5Credentials.times.endtime;
        TimetToFileTime(tt, &eft);
        kcdb_cred_set_attr(cred, KCDB_ATTR_EXPIRE, &eft, sizeof(eft));

        {
            FILETIME ftl;

            ftl = FtSub(&eft, &ft);
            kcdb_cred_set_attr(cred, KCDB_ATTR_LIFETIME, &ftl, sizeof(ftl));
        }

        if (KRBv5Credentials.times.renew_till > 0) {
            FILETIME ftl;

            tt = KRBv5Credentials.times.renew_till;
            TimetToFileTime(tt, &eft);
            kcdb_cred_set_attr(cred, KCDB_ATTR_RENEW_EXPIRE, &eft, 
                               sizeof(eft));


            ftl = FtSub(&eft, &ft);
            kcdb_cred_set_attr(cred, KCDB_ATTR_RENEW_LIFETIME, &ftl, 
                               sizeof(ftl));
        }

        ti = KRBv5Credentials.ticket_flags;
        kcdb_cred_set_attr(cred, attr_id_krb5_flags, &ti, sizeof(ti));

        /* special flags understood by NetIDMgr */
        {
            khm_int32 nflags = 0;

            if (ti & TKT_FLG_RENEWABLE)
                nflags |= KCDB_CRED_FLAG_RENEWABLE;
            if (ti & TKT_FLG_INITIAL)
                nflags |= KCDB_CRED_FLAG_INITIAL;
	    else {
		krb5_data * c0, *c1, *r;

		/* these are macros that do not allocate any memory */
		c0 = krb5_princ_component(ctx,KRBv5Credentials.server,0);
		c1 = krb5_princ_component(ctx,KRBv5Credentials.server,1);
		r  = krb5_princ_realm(ctx,KRBv5Credentials.server);

		if ( c0 && c1 && r && c1->length == r->length && 
		     !strncmp(c1->data,r->data,r->length) &&
		     !strncmp("krbtgt",c0->data,c0->length) )
		    nflags |= KCDB_CRED_FLAG_INITIAL;
	    }

            kcdb_cred_set_flags(cred, nflags, KCDB_CRED_FLAGMASK_EXT);

            cred_flags = nflags;
        }

        if ( !pkrb5_decode_ticket(&KRBv5Credentials.ticket, &tkt)) {
            ti = tkt->enc_part.enctype;
            kcdb_cred_set_attr(cred, attr_id_tkt_enctype, &ti, sizeof(ti));
            pkrb5_free_ticket(ctx, tkt);
            tkt = NULL;
        }

        ti = KRBv5Credentials.keyblock.enctype;
        kcdb_cred_set_attr(cred, attr_id_key_enctype, &ti, sizeof(ti));
        kcdb_cred_set_attr(cred, KCDB_ATTR_LOCATION, wcc_name, 
                           KCDB_CBSIZE_AUTO);

        if ( KRBv5Credentials.addresses && KRBv5Credentials.addresses[0] ) {
	    khm_int32 buffer[1024];
	    void * bufp;
	    khm_size cb;
	    khm_int32 rv;

	    bufp = (void *) buffer;
	    cb = sizeof(buffer);

	    rv = serialize_krb5_addresses(KRBv5Credentials.addresses,
					  bufp,
					  &cb);
	    if (rv == KHM_ERROR_TOO_LONG) {
		bufp = PMALLOC(cb);
		rv = serialize_krb5_addresses(KRBv5Credentials.addresses,
					      bufp,
					      &cb);
	    }

	    if (KHM_SUCCEEDED(rv)) {
		kcdb_cred_set_attr(cred, attr_id_addr_list,
				   bufp, cb);
	    }

	    if (bufp != (void *) buffer)
		PFREE(bufp);
        }

        if(cred_flags & KCDB_CRED_FLAG_INITIAL) {
            FILETIME ft_issue_new;
            FILETIME ft_expire_old;
            FILETIME ft_expire_new;
            khm_size cb;

            /* an initial ticket!  If we find one, we generally set
               the lifetime, and primary ccache based on this, but
               only if this initial cred has a greater lifetime than
               the current primary credential. */

            tt = KRBv5Credentials.times.endtime;
            TimetToFileTime(tt, &ft_expire_new);

            tt = KRBv5Credentials.times.starttime;
            TimetToFileTime(tt, &ft_issue_new);

            cb = sizeof(ft_expire_old);
            if(KHM_FAILED(kcdb_identity_get_attr(tident, 
                                                 KCDB_ATTR_EXPIRE, 
                                                 NULL, &ft_expire_old, 
                                                 &cb))
               || CompareFileTime(&ft_expire_new, &ft_expire_old) > 0) {

                kcdb_identity_set_attr(tident, attr_id_krb5_ccname, 
                                       wcc_name, KCDB_CBSIZE_AUTO);
                kcdb_identity_set_attr(tident, KCDB_ATTR_EXPIRE, 
                                       &ft_expire_new, 
                                       sizeof(ft_expire_new));
                kcdb_identity_set_attr(tident, KCDB_ATTR_ISSUE,
                                       &ft_issue_new,
                                       sizeof(ft_issue_new));

                if (KRBv5Credentials.times.renew_till > 0) {
                    tt = KRBv5Credentials.times.renew_till;
                    TimetToFileTime(tt, &ft);
                    kcdb_identity_set_attr(tident, 
                                           KCDB_ATTR_RENEW_EXPIRE, 
                                           &ft, sizeof(ft));
                } else {
                    kcdb_identity_set_attr(tident,
                                           KCDB_ATTR_RENEW_EXPIRE,
                                           NULL, 0);
                }

                ti = KRBv5Credentials.ticket_flags;
                kcdb_identity_set_attr(tident, attr_id_krb5_flags, 
                                       &ti, sizeof(ti));
            }
        }

        kcdb_credset_add_cred(krb5_credset, cred, -1);

        (*pkrb5_free_cred_contents)(ctx, &KRBv5Credentials);

        if(tident != ident)
            kcdb_identity_release(tident);
    }

    if (PrincipalName != NULL)
        (*pkrb5_free_unparsed_name)(ctx, PrincipalName);

    if (ClientName != NULL)
        (*pkrb5_free_unparsed_name)(ctx, ClientName);

    if (sServerName != NULL)
        (*pkrb5_free_unparsed_name)(ctx, sServerName);

    if (cred)
        kcdb_cred_release(cred);

    if ((code == KRB5_CC_END) || (code == KRB5_CC_NOTFOUND))
    {
        if ((code = pkrb5_cc_end_seq_get(ctx, cache, &KRBv5Cursor))) 
        {
            goto _exit;
        }

        flags = KRB5_TC_OPENCLOSE;
#ifdef KRB5_TC_NOTICKET
        flags |= KRB5_TC_NOTICKET;
#endif
        if ((code = pkrb5_cc_set_flags(ctx, cache, flags))) 
        {
            goto _exit;
        }
    }
    else 
    {
        goto _exit;
    }

_exit:

    return code;
}

long
khm_krb5_list_tickets(krb5_context *krbv5Context)
{
    krb5_context	ctx = NULL;
    krb5_ccache		cache = 0;
    krb5_error_code	code = 0;
    apiCB *             cc_ctx = 0;
    struct _infoNC **   pNCi = NULL;
    int                 i;
    khm_int32           t;
    wchar_t *           ms = NULL;
    khm_size            cb;

    kcdb_credset_flush(krb5_credset);

    if((*krbv5Context == 0) && (code = (*pkrb5_init_context)(krbv5Context))) {
        goto _exit;
    }

    ctx = (*krbv5Context);

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
        char ccname[KRB5_MAXCCH_CCNAME];

        if (pNCi[i]->vers != CC_CRED_V5)
            continue;

        if (FAILED(StringCchPrintfA(ccname, sizeof(ccname), "API:%s",
                                    pNCi[i]->name)))
            continue;

        code = (*pkrb5_cc_resolve)(ctx, ccname, &cache);

        if (code)
            continue;

        code = get_tickets_from_cache(ctx, cache);

        if(ctx != NULL && cache != NULL)
            (*pkrb5_cc_close)(ctx, cache);

        cache = 0;
    }

 _skip_cc_iter:

    if (KHM_SUCCEEDED(khc_read_int32(csp_params, L"MsLsaList", &t)) && t) {
        code = (*pkrb5_cc_resolve)(ctx, "MSLSA:", &cache);

        if (code == 0 && cache) {
            code = get_tickets_from_cache(ctx, cache);
        }

        if (ctx != NULL && cache != NULL)
            (*pkrb5_cc_close)(ctx, cache);
        cache = 0;
    }

    if (khc_read_multi_string(csp_params, L"FileCCList", NULL, &cb)
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

            code = get_tickets_from_cache(ctx, cache);

            if (ctx != NULL && cache != NULL)
                (*pkrb5_cc_close)(ctx, cache);
            cache = 0;
        }

        PFREE(ms);
    }

_exit:
    if (pNCi)
        (*pcc_free_NC_info)(cc_ctx, &pNCi);
    if (cc_ctx)
        (*pcc_shutdown)(&cc_ctx);

    kcdb_credset_collect(NULL, krb5_credset, NULL, credtype_id_krb5, NULL);

    return(code);
}

int
khm_krb5_renew_cred(khm_handle cred)
{
    khm_handle          identity = NULL;
    krb5_error_code     code = 0;
    krb5_context        ctx = 0;
    krb5_ccache         cc = 0;

    if (cred == NULL) {
#ifdef DEBUG
	assert(FALSE);
#endif
	goto _cleanup;
    }

    if (KHM_FAILED(kcdb_cred_get_identity(cred, &identity))) {
#ifdef DEBUG
	assert(FALSE);
#endif
	goto _cleanup;
    }

    code = khm_krb5_initialize(identity, &ctx, &cc);
    if (code)
	goto _cleanup;

    /* TODO: going here */

 _cleanup:

    if (identity)
	kcdb_identity_release(identity);

    if (cc && ctx)
	pkrb5_cc_close(ctx, cc);

    if (ctx)
	pkrb5_free_context(ctx);

    return code;
}

int
khm_krb5_renew_ident(khm_handle identity)
{
    krb5_error_code     code = 0;
    krb5_context        ctx = 0;
    krb5_ccache         cc = 0;
    krb5_principal      me = 0;
    krb5_principal      server = 0;
    krb5_creds          my_creds;
    krb5_data           *realm = 0;

    memset(&my_creds, 0, sizeof(krb5_creds));

    if ( !pkrb5_init_context )
        goto cleanup;

    code = khm_krb5_initialize(identity, &ctx, &cc);
    if (code) 
        goto cleanup;

    code = pkrb5_cc_get_principal(ctx, cc, &me);
    if (code) 
        goto cleanup;

    realm = krb5_princ_realm(ctx, me);

    code = pkrb5_build_principal_ext(ctx, &server,
                                     realm->length,realm->data,
                                     KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                     realm->length,realm->data,
                                     0);

    if (code) 
        goto cleanup;

    my_creds.client = me;
    my_creds.server = server;

#ifdef KRB5_TC_NOTICKET
    pkrb5_cc_set_flags(ctx, cc, 0);
#endif
    code = pkrb5_get_renewed_creds(ctx, &my_creds, me, cc, NULL);
#ifdef KRB5_TC_NOTICKET
    pkrb5_cc_set_flags(ctx, cc, KRB5_TC_NOTICKET);
#endif
    if (code) {
        if ( code != KRB5KDC_ERR_ETYPE_NOSUPP ||
            code != KRB5_KDC_UNREACH)
            khm_krb5_error(code, "krb5_get_renewed_creds()", 0, &ctx, &cc);
        goto cleanup;
    }

    code = pkrb5_cc_initialize(ctx, cc, me);
    if (code) goto cleanup;

    code = pkrb5_cc_store_cred(ctx, cc, &my_creds);
    if (code) goto cleanup;

cleanup:
    if (my_creds.client == me)
        my_creds.client = 0;
    if (my_creds.server == server)
        my_creds.server = 0;

    pkrb5_free_cred_contents(ctx, &my_creds);

    if (me)
        pkrb5_free_principal(ctx, me);
    if (server)
        pkrb5_free_principal(ctx, server);
    if (cc)
        pkrb5_cc_close(ctx, cc);
    if (ctx)
        pkrb5_free_context(ctx);
    return(code);
}

int
khm_krb5_kinit(krb5_context       alt_ctx,
               char *             principal_name,
               char *             password,
               char *             ccache,
               krb5_deltat        lifetime,
               DWORD              forwardable,
               DWORD              proxiable,
               krb5_deltat        renew_life,
               DWORD              addressless,
               DWORD              publicIP,
               krb5_prompter_fct  prompter,
               void *             p_data)
{
    krb5_error_code		        code = 0;
    krb5_context		        ctx = 0;
    krb5_ccache			        cc = 0;
    krb5_principal		        me = 0;
    char*                       name = 0;
    krb5_creds			        my_creds;
    krb5_get_init_creds_opt     options;
    krb5_address **             addrs = NULL;
    int                         i = 0, addr_count = 0;

    if (!pkrb5_init_context)
        return 0;

    _reportf(L"In khm_krb5_kinit");

    pkrb5_get_init_creds_opt_init(&options);
    memset(&my_creds, 0, sizeof(my_creds));

    if (alt_ctx) {
        ctx = alt_ctx;
    } else {
        code = pkrb5_init_context(&ctx);
        if (code)
            goto cleanup;
    }

    if (ccache) {
        _reportf(L"Using supplied ccache name %S", ccache);
        code = pkrb5_cc_resolve(ctx, ccache, &cc);
    } else {
	khm_handle identity = NULL;
	khm_handle csp_ident = NULL;
	khm_handle csp_k5 = NULL;
	wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
	wchar_t wccname[MAX_PATH];
	char ccname[MAX_PATH];
	char * pccname = principal_name;
	khm_size cb;

	idname[0] = L'\0';
	AnsiStrToUnicode(idname, sizeof(idname), principal_name);

	cb = sizeof(wccname);

	if (KHM_SUCCEEDED(kcdb_identity_create(idname, 0, &identity)) &&

	    KHM_SUCCEEDED(kcdb_identity_get_config(identity, 0, &csp_ident)) &&

	    KHM_SUCCEEDED(khc_open_space(csp_ident, CSNAME_KRB5CRED, 0,
					 &csp_k5)) &&

	    KHM_SUCCEEDED(khc_read_string(csp_k5, L"DefaultCCName",
					  wccname, &cb)) &&

	    cb > sizeof(wchar_t)) {

            _reportf(L"Using DefaultCCName [%s] from identity", wccname);

	    UnicodeStrToAnsi(ccname, sizeof(ccname), wccname);
	    pccname = ccname;
	}

	if (csp_k5)
	    khc_close_space(csp_k5);
	if (csp_ident)
	    khc_close_space(csp_ident);
	if (identity)
	    kcdb_identity_release(identity);

        code = pkrb5_cc_resolve(ctx, pccname, &cc);
    }

    _reportf(L"krb5_cc_resolve returns code %d", code);

    if (code) goto cleanup;

    code = pkrb5_parse_name(ctx, principal_name, &me);
    if (code) goto cleanup;

    code = pkrb5_unparse_name(ctx, me, &name);
    if (code) goto cleanup;

    if (lifetime == 0) {
        khc_read_int32(csp_params, L"DefaultLifetime", &lifetime);
    }

    if (lifetime)
        pkrb5_get_init_creds_opt_set_tkt_life(&options, lifetime);

    pkrb5_get_init_creds_opt_set_forwardable(&options,
        forwardable ? 1 : 0);
    pkrb5_get_init_creds_opt_set_proxiable(&options,
        proxiable ? 1 : 0);
    pkrb5_get_init_creds_opt_set_renew_life(&options,
        renew_life);

    if (addressless)
        pkrb5_get_init_creds_opt_set_address_list(&options,NULL);
    else {
	krb5_address ** local_addrs=NULL;
	DWORD           netIPAddr;

	pkrb5_os_localaddr(ctx, &local_addrs);
	i = 0;
	while ( local_addrs[i++] );
	addr_count = i + 1;

	addrs = (krb5_address **) PMALLOC((addr_count+1) * sizeof(krb5_address *));
	if ( !addrs ) {
	    pkrb5_free_addresses(ctx, local_addrs);
	    assert(0);
	}
	memset(addrs, 0, sizeof(krb5_address *) * (addr_count+1));
	i = 0;
	while ( local_addrs[i] ) {
	    addrs[i] = (krb5_address *)PMALLOC(sizeof(krb5_address));
	    if (addrs[i] == NULL) {
		pkrb5_free_addresses(ctx, local_addrs);
		assert(0);
	    }

	    addrs[i]->magic = local_addrs[i]->magic;
	    addrs[i]->addrtype = local_addrs[i]->addrtype;
	    addrs[i]->length = local_addrs[i]->length;
	    addrs[i]->contents = (unsigned char *)PMALLOC(addrs[i]->length);
	    if (!addrs[i]->contents) {
		pkrb5_free_addresses(ctx, local_addrs);
		assert(0);
	    }

	    memcpy(addrs[i]->contents,local_addrs[i]->contents,
		   local_addrs[i]->length);        /* safe */
	    i++;
	}
	pkrb5_free_addresses(ctx, local_addrs);

        if (publicIP) {
            // we are going to add the public IP address specified by the user
            // to the list provided by the operating system
            addrs[i] = (krb5_address *)PMALLOC(sizeof(krb5_address));
            if (addrs[i] == NULL)
                assert(0);

            addrs[i]->magic = KV5M_ADDRESS;
            addrs[i]->addrtype = AF_INET;
            addrs[i]->length = 4;
            addrs[i]->contents = (unsigned char *)PMALLOC(addrs[i]->length);
            if (!addrs[i]->contents)
                assert(0);

            netIPAddr = htonl(publicIP);
            memcpy(addrs[i]->contents,&netIPAddr,4);
        }

	pkrb5_get_init_creds_opt_set_address_list(&options,addrs);
    }

    code =
        pkrb5_get_init_creds_password(ctx,
                                      &my_creds,
                                      me,
                                      password, // password
                                      prompter, // prompter
                                      p_data, // prompter data
                                      0, // start time
                                      0, // service name
                                      &options);
    _reportf(L"krb5_get_init_creds_password returns code %d", code);

    if (code) goto cleanup;

    code = pkrb5_cc_initialize(ctx, cc, me);
    _reportf(L"krb5_cc_initialize returns code %d", code);
    if (code) goto cleanup;

    code = pkrb5_cc_store_cred(ctx, cc, &my_creds);
    _reportf(L"krb5_cc_store_cred returns code %d", code);
    if (code) goto cleanup;

cleanup:
    if ( addrs ) {
        for ( i=0;i<addr_count;i++ ) {
            if ( addrs[i] ) {
                if ( addrs[i]->contents )
                    PFREE(addrs[i]->contents);
                PFREE(addrs[i]);
            }
        }
    }
    if (my_creds.client == me)
        my_creds.client = 0;
    pkrb5_free_cred_contents(ctx, &my_creds);
    if (name)
        pkrb5_free_unparsed_name(ctx, name);
    if (me)
        pkrb5_free_principal(ctx, me);
    if (cc)
        pkrb5_cc_close(ctx, cc);
    if (ctx && (ctx != alt_ctx))
        pkrb5_free_context(ctx);
    return(code);
}

long
khm_krb5_copy_ccache_by_name(krb5_context in_ctx,
                             wchar_t * wscc_dest,
                             wchar_t * wscc_src) {
    krb5_context ctx = NULL;
    krb5_error_code code = 0;
    khm_boolean free_ctx;
    krb5_ccache cc_src = NULL;
    krb5_ccache cc_dest = NULL;
    krb5_principal princ_src = NULL;
    char scc_dest[KRB5_MAXCCH_CCNAME];
    char scc_src[KRB5_MAXCCH_CCNAME];
    int t;

    t = UnicodeStrToAnsi(scc_dest, sizeof(scc_dest), wscc_dest);
    if (t == 0)
        return KHM_ERROR_TOO_LONG;
    t = UnicodeStrToAnsi(scc_src, sizeof(scc_src), wscc_src);
    if (t == 0)
        return KHM_ERROR_TOO_LONG;

    if (in_ctx) {
        ctx = in_ctx;
        free_ctx = FALSE;
    } else {
        code = pkrb5_init_context(&ctx);
        if (code) {
            if (ctx)
                pkrb5_free_context(ctx);
            return code;
        }
        free_ctx = TRUE;
    }

    code = pkrb5_cc_resolve(ctx, scc_dest, &cc_dest);
    if (code)
        goto _cleanup;

    code = pkrb5_cc_resolve(ctx, scc_src, &cc_src);
    if (code)
        goto _cleanup;

    code = pkrb5_cc_get_principal(ctx, cc_src, &princ_src);
    if (code)
        goto _cleanup;

    code = pkrb5_cc_initialize(ctx, cc_dest, princ_src);
    if (code)
        goto _cleanup;

    code = pkrb5_cc_copy_creds(ctx, cc_src, cc_dest);

 _cleanup:
    if (princ_src)
        pkrb5_free_principal(ctx, princ_src);

    if (cc_dest)
        pkrb5_cc_close(ctx, cc_dest);

    if (cc_src)
        pkrb5_cc_close(ctx, cc_src);

    if (free_ctx && ctx)
        pkrb5_free_context(ctx);

    return code;
}

long
khm_krb5_canon_cc_name(wchar_t * wcc_name,
                       size_t cb_cc_name) {
    size_t cb_len;
    wchar_t * colon;

    if (FAILED(StringCbLength(wcc_name, 
                              cb_cc_name,
                              &cb_len))) {
#ifdef DEBUG
        assert(FALSE);
#else
        return KHM_ERROR_TOO_LONG;
#endif
    }

    cb_len += sizeof(wchar_t);

    colon = wcschr(wcc_name, L':');

    if (colon) {
        /* if the colon is just 1 character away from the beginning,
           it's a FILE: cc */
        if (colon - wcc_name == 1) {
            if (cb_len + 5 * sizeof(wchar_t) > cb_cc_name)
                return KHM_ERROR_TOO_LONG;

            memmove(&wcc_name[5], &wcc_name[0], cb_len);
            memmove(&wcc_name[0], L"FILE:", sizeof(wchar_t) * 5);
        }

        return 0;
    }

    if (cb_len + 4 * sizeof(wchar_t) > cb_cc_name)
        return KHM_ERROR_TOO_LONG;

    memmove(&wcc_name[4], &wcc_name[0], cb_len);
    memmove(&wcc_name[0], L"API:", sizeof(wchar_t) * 4);

    return 0;
}

int 
khm_krb5_cc_name_cmp(const wchar_t * cc_name_1,
                     const wchar_t * cc_name_2) {
    if (!wcsncmp(cc_name_1, L"API:", 4))
        cc_name_1 += 4;

    if (!wcsncmp(cc_name_2, L"API:", 4))
        cc_name_2 += 4;

    return wcscmp(cc_name_1, cc_name_2);
}

static khm_int32 KHMAPI
khmint_location_comp_func(khm_handle cred1,
                          khm_handle cred2,
                          void * rock) {
    return kcdb_creds_comp_attr(cred1, cred2, KCDB_ATTR_LOCATION);
}

struct khmint_location_check {
    khm_handle credset;
    khm_handle cred;
    wchar_t * ccname;
    khm_boolean success;
};

static khm_int32 KHMAPI
khmint_find_matching_cred_func(khm_handle cred,
                               void * rock) {
    struct khmint_location_check * lc;

    lc = (struct khmint_location_check *) rock;

    if (!kcdb_creds_is_equal(cred, lc->cred))
        return KHM_ERROR_SUCCESS;
    if (kcdb_creds_comp_attr(cred, lc->cred, KCDB_ATTR_LOCATION))
        return KHM_ERROR_SUCCESS;

    /* found it */
    lc->success = TRUE;

    /* break the search */
    return !KHM_ERROR_SUCCESS;
}

static khm_int32 KHMAPI
khmint_location_check_func(khm_handle cred,
                           void * rock) {
    khm_int32 t;
    khm_size cb;
    wchar_t ccname[KRB5_MAXCCH_CCNAME];
    struct khmint_location_check * lc;

    lc = (struct khmint_location_check *) rock;

    if (KHM_FAILED(kcdb_cred_get_type(cred, &t)))
        return KHM_ERROR_SUCCESS;

    if (t != credtype_id_krb5)
        return KHM_ERROR_SUCCESS;

    cb = sizeof(ccname);
    if (KHM_FAILED(kcdb_cred_get_attr(cred,
                                      KCDB_ATTR_LOCATION,
                                      NULL,
                                      ccname,
                                      &cb)))
        return KHM_ERROR_SUCCESS;

    if(wcscmp(ccname, lc->ccname))
        return KHM_ERROR_SUCCESS;

    lc->cred = cred;

    lc->success = FALSE;

    kcdb_credset_apply(lc->credset,
                       khmint_find_matching_cred_func,
                       (void *) lc);

    if (!lc->success)
        return KHM_ERROR_NOT_FOUND;
    else
        return KHM_ERROR_SUCCESS;
}

static khm_int32 KHMAPI
khmint_delete_location_func(khm_handle cred,
                            void * rock) {
    wchar_t cc_cred[KRB5_MAXCCH_CCNAME];
    struct khmint_location_check * lc;
    khm_size cb;

    lc = (struct khmint_location_check *) rock;

    cb = sizeof(cc_cred);

    if (KHM_FAILED(kcdb_cred_get_attr(cred,
                                      KCDB_ATTR_LOCATION,
                                      NULL,
                                      cc_cred,
                                      &cb)))
        return KHM_ERROR_SUCCESS;

    if (wcscmp(cc_cred, lc->ccname))
        return KHM_ERROR_SUCCESS;

    kcdb_credset_del_cred_ref(lc->credset,
                              cred);

    return KHM_ERROR_SUCCESS;
}

int
khm_krb5_destroy_by_credset(khm_handle p_cs)
{
    khm_handle d_cs = NULL;
    khm_int32 rv = KHM_ERROR_SUCCESS;
    khm_size s, cb;
    krb5_context ctx;
    krb5_error_code code = 0;
    int i;
    wchar_t ccname[KRB5_MAXCCH_CCNAME];
    struct khmint_location_check lc;

    rv = kcdb_credset_create(&d_cs);

    assert(KHM_SUCCEEDED(rv) && d_cs != NULL);

    kcdb_credset_extract(d_cs, p_cs, NULL, credtype_id_krb5);

    kcdb_credset_get_size(d_cs, &s);

    if (s == 0) {
        _reportf(L"No tickets to delete");

        kcdb_credset_delete(d_cs);
        return 0;
    }

    code = pkrb5_init_context(&ctx);
    if (code != 0) {
        rv = code;
        goto _cleanup;
    }

    /* we should synchronize the credential lists before we attempt to
       make any assumptions on the state of the root credset */
    khm_krb5_list_tickets(&ctx);

    /* so, we need to make a decision about whether to destroy entire
       ccaches or just individual credentials.  Therefore we first
       sort them by ccache. */
    kcdb_credset_sort(d_cs,
                      khmint_location_comp_func,
                      NULL);

    /* now, for each ccache we encounter, we check if we have all the
       credentials from that ccache in the to-be-deleted list. */
    for (i=0; i < (int) s; i++) {
        khm_handle cred;

        if (KHM_FAILED(kcdb_credset_get_cred(d_cs,
                                             i,
                                             &cred)))
            continue;

        cb = sizeof(ccname);
        rv = kcdb_cred_get_attr(cred,
                                KCDB_ATTR_LOCATION,
                                NULL,
                                ccname,
                                &cb);

#ifdef DEBUG
        assert(KHM_SUCCEEDED(rv));
#endif
        kcdb_cred_release(cred);

        lc.credset = d_cs;
        lc.cred = NULL;
        lc.ccname = ccname;
        lc.success = FALSE;

        kcdb_credset_apply(NULL,
                           khmint_location_check_func,
                           (void *) &lc);

        if (lc.success) {
            /* ok the destroy the ccache */
            char a_ccname[KRB5_MAXCCH_CCNAME];
            krb5_ccache cc = NULL;

            _reportf(L"Destroying ccache [%s]", ccname);

            UnicodeStrToAnsi(a_ccname,
                             sizeof(a_ccname),
                             ccname);

            code = pkrb5_cc_resolve(ctx,
                                    a_ccname,
                                    &cc);
            if (code)
                goto _delete_this_set;

            code = pkrb5_cc_destroy(ctx, cc);

            if (code) {
                _reportf(L"krb5_cc_destroy returns code %d", code);
            }

        _delete_this_set:

            lc.credset = d_cs;
            lc.ccname = ccname;

            /* note that although we are deleting credentials off the
               credential set, the size of the credential set does not
               decrease since we are doing it from inside
               kcdb_credset_apply().  The deleted creds will simply be
               marked as deleted until kcdb_credset_purge() is
               called. */

            kcdb_credset_apply(d_cs,
                               khmint_delete_location_func,
                               (void *) &lc);
        }
    }

    kcdb_credset_purge(d_cs);

    /* the remainder need to be deleted one by one */

    kcdb_credset_get_size(d_cs, &s);

    for (i=0; i < (int) s; ) {
        khm_handle cred;
        char a_ccname[KRB5_MAXCCH_CCNAME];
        char a_srvname[KCDB_CRED_MAXCCH_NAME];
        wchar_t srvname[KCDB_CRED_MAXCCH_NAME];
        krb5_ccache cc;
        krb5_creds in_cred, out_cred;
        krb5_principal princ;
        khm_int32 etype;

        if (KHM_FAILED(kcdb_credset_get_cred(d_cs,
                                             i,
                                             &cred))) {
            i++;
            continue;
        }

        cb = sizeof(ccname);
        if (KHM_FAILED(kcdb_cred_get_attr(cred,
                                          KCDB_ATTR_LOCATION,
                                          NULL,
                                          ccname,
                                          &cb)))
            goto _done_with_this_cred;

        _reportf(L"Looking at ccache [%s]", ccname);

        UnicodeStrToAnsi(a_ccname,
                         sizeof(a_ccname),
                         ccname);

        code = pkrb5_cc_resolve(ctx,
                                a_ccname,
                                &cc);

        if (code)
            goto _skip_similar;

        code = pkrb5_cc_get_principal(ctx, cc, &princ);

        if (code) {
            pkrb5_cc_close(ctx, cc);
            goto _skip_similar;
        }

    _del_this_cred:

        cb = sizeof(etype);

        if (KHM_FAILED(kcdb_cred_get_attr(cred,
                                          attr_id_key_enctype,
                                          NULL,
                                          &etype,
                                          &cb)))
            goto _do_next_cred;

        cb = sizeof(srvname);
        if (KHM_FAILED(kcdb_cred_get_name(cred,
                                          srvname,
                                          &cb)))
            goto _do_next_cred;

        _reportf(L"Attempting to delete ticket %s", srvname);

        UnicodeStrToAnsi(a_srvname, sizeof(a_srvname), srvname);

        ZeroMemory(&in_cred, sizeof(in_cred));

        code = pkrb5_parse_name(ctx, a_srvname, &in_cred.server);
        if (code)
            goto _do_next_cred;
        in_cred.client = princ;
        in_cred.keyblock.enctype = etype;

        code = pkrb5_cc_retrieve_cred(ctx,
                                      cc,
                                      KRB5_TC_MATCH_SRV_NAMEONLY |
                                      KRB5_TC_SUPPORTED_KTYPES,
                                      &in_cred,
                                      &out_cred);
        if (code)
            goto _do_next_cred_0;

        code = pkrb5_cc_remove_cred(ctx, cc,
                                    KRB5_TC_MATCH_SRV_NAMEONLY |
                                    KRB5_TC_SUPPORTED_KTYPES |
                                    KRB5_TC_MATCH_AUTHDATA,
                                    &out_cred);

        pkrb5_free_cred_contents(ctx, &out_cred);
    _do_next_cred_0:
        pkrb5_free_principal(ctx, in_cred.server);
    _do_next_cred:

        /* check if the next cred is also of the same ccache */
        kcdb_cred_release(cred);

        for (i++; i < (int) s; i++) {
            if (KHM_FAILED(kcdb_credset_get_cred(d_cs,
                                                 i,
                                                 &cred)))
                continue;
        }

        if (i < (int) s) {
            wchar_t newcc[KRB5_MAXCCH_CCNAME];

            cb = sizeof(newcc);
            if (KHM_FAILED(kcdb_cred_get_attr(cred,
                                              KCDB_ATTR_LOCATION,
                                              NULL,
                                              newcc,
                                              &cb)) ||
                wcscmp(newcc, ccname)) {
                i--;            /* we have to look at this again */
                goto _done_with_this_set;
            }
            goto _del_this_cred;
        }
        

    _done_with_this_set:
        pkrb5_free_principal(ctx, princ);

        pkrb5_cc_close(ctx, cc);

    _done_with_this_cred:
        kcdb_cred_release(cred);
        i++;
        continue;

    _skip_similar:
        kcdb_cred_release(cred);

        for (++i; i < (int) s; i++) {
            wchar_t newcc[KRB5_MAXCCH_CCNAME];

            if (KHM_FAILED(kcdb_credset_get_cred(d_cs,
                                                 i,
                                                 &cred)))
                continue;

            cb = sizeof(newcc);
            if (KHM_FAILED(kcdb_cred_get_attr(cred,
                                              KCDB_ATTR_LOCATION,
                                              NULL,
                                              &newcc,
                                              &cb))) {
                kcdb_cred_release(cred);
                continue;
            }

            if (wcscmp(newcc, ccname)) {
                kcdb_cred_release(cred);
                break;
            }
        }
    }

 _cleanup:

    if (d_cs)
        kcdb_credset_delete(&d_cs);

    return rv;
}

int
khm_krb5_destroy_identity(khm_handle identity)
{
    krb5_context		ctx;
    krb5_ccache			cache;
    krb5_error_code		rc;

    ctx = NULL;
    cache = NULL;

    if (rc = khm_krb5_initialize(identity, &ctx, &cache))
        return(rc);

    rc = pkrb5_cc_destroy(ctx, cache);

    if (ctx != NULL)
        pkrb5_free_context(ctx);

    return(rc);
}

static BOOL
GetSecurityLogonSessionData(PSECURITY_LOGON_SESSION_DATA * ppSessionData)
{
    NTSTATUS Status = 0;
    HANDLE  TokenHandle;
    TOKEN_STATISTICS Stats;
    DWORD   ReqLen;
    BOOL    Success;

    if (!ppSessionData)
        return FALSE;
    *ppSessionData = NULL;

    Success = OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &TokenHandle );
    if ( !Success )
        return FALSE;

    Success = GetTokenInformation( TokenHandle, TokenStatistics, &Stats, sizeof(TOKEN_STATISTICS), &ReqLen );
    CloseHandle( TokenHandle );
    if ( !Success )
        return FALSE;

    Status = pLsaGetLogonSessionData( &Stats.AuthenticationId, ppSessionData );
    if ( FAILED(Status) || !ppSessionData )
        return FALSE;

    return TRUE;
}

// IsKerberosLogon() does not validate whether or not there are valid
// tickets in the cache.  It validates whether or not it is reasonable
// to assume that if we attempted to retrieve valid tickets we could
// do so.  Microsoft does not automatically renew expired tickets.
// Therefore, the cache could contain expired or invalid tickets.
// Microsoft also caches the user's password and will use it to
// retrieve new TGTs if the cache is empty and tickets are requested.

static BOOL
IsKerberosLogon(VOID)
{
    PSECURITY_LOGON_SESSION_DATA pSessionData = NULL;
    BOOL    Success = FALSE;

    if ( GetSecurityLogonSessionData(&pSessionData) ) {
        if ( pSessionData->AuthenticationPackage.Buffer ) {
            WCHAR buffer[256];
            WCHAR *usBuffer;
            int usLength;

            Success = FALSE;
            usBuffer = (pSessionData->AuthenticationPackage).Buffer;
            usLength = (pSessionData->AuthenticationPackage).Length;
            if (usLength < 256)
            {
                lstrcpynW (buffer, usBuffer, usLength);
                StringCbCatW (buffer, sizeof(buffer), L"");
                if ( !lstrcmpW(L"Kerberos",buffer) )
                    Success = TRUE;
            }
        }
        pLsaFreeReturnBuffer(pSessionData);
    }
    return Success;
}


BOOL
khm_krb5_ms2mit(BOOL save_creds)
{
#ifdef NO_KRB5
    return(FALSE);
#else /* NO_KRB5 */
    krb5_context kcontext = 0;
    krb5_error_code code = 0;
    krb5_ccache ccache=0;
    krb5_ccache mslsa_ccache=0;
    krb5_creds creds;
    krb5_cc_cursor cursor=0;
    krb5_principal princ = 0;
    char *cache_name = NULL;
    char *princ_name = NULL;
    BOOL rc = FALSE;

    kherr_reportf(L"Begin : khm_krb5_ms2mit. save_cred=%d\n", (int) save_creds);

    if ( !pkrb5_init_context )
        goto cleanup;

    if (code = pkrb5_init_context(&kcontext))
        goto cleanup;

    kherr_reportf(L"Resolving MSLSA\n");

    if (code = pkrb5_cc_resolve(kcontext, "MSLSA:", &mslsa_ccache))
        goto cleanup;

    if ( save_creds ) {
        kherr_reportf(L"Getting principal\n");
        if (code = pkrb5_cc_get_principal(kcontext, mslsa_ccache, &princ))
            goto cleanup;

        kherr_reportf(L"Unparsing name\n");
        if (code = pkrb5_unparse_name(kcontext, princ, &princ_name))
            goto cleanup;

        kherr_reportf(L"Unparsed [%S].  Resolving target cache\n", princ_name);
        /* TODO: actually look up the preferred ccache name */
        if (code = pkrb5_cc_resolve(kcontext, princ_name, &ccache)) {
            kherr_reportf(L"Cannot resolve cache [%S] with code=%d.  Trying default.\n", princ_name, code);

            if (code = pkrb5_cc_default(kcontext, &ccache)) {
                kherr_reportf(L"Failed to resolve default ccache. Code=%d", code);
                goto cleanup;
            }
        }

        kherr_reportf(L"Initializing ccache\n");
        if (code = pkrb5_cc_initialize(kcontext, ccache, princ))
            goto cleanup;

        kherr_reportf(L"Copying credentials\n");
        if (code = pkrb5_cc_copy_creds(kcontext, mslsa_ccache, ccache))
            goto cleanup;

        rc = TRUE;
    } else {
        /* Enumerate tickets from cache looking for an initial ticket */
        if ((code = pkrb5_cc_start_seq_get(kcontext, mslsa_ccache, &cursor))) 
            goto cleanup;

        while (!(code = pkrb5_cc_next_cred(kcontext, mslsa_ccache, 
                                           &cursor, &creds))) {
            if ( creds.ticket_flags & TKT_FLG_INITIAL ) {
                rc = TRUE;
                pkrb5_free_cred_contents(kcontext, &creds);
                break;
            }
            pkrb5_free_cred_contents(kcontext, &creds);
        }
        pkrb5_cc_end_seq_get(kcontext, mslsa_ccache, &cursor);
    }

cleanup:
    kherr_reportf(L"  Received code=%d", code);

    if (princ_name)
        pkrb5_free_unparsed_name(kcontext, princ_name);
    if (princ)
        pkrb5_free_principal(kcontext, princ);
    if (ccache)
        pkrb5_cc_close(kcontext, ccache);
    if (mslsa_ccache)
        pkrb5_cc_close(kcontext, mslsa_ccache);
    if (kcontext)
        pkrb5_free_context(kcontext);
    return(rc);
#endif /* NO_KRB5 */
}

#define KRB_FILE                "KRB.CON"
#define KRBREALM_FILE           "KRBREALM.CON"
#define KRB5_FILE               "KRB5.INI"
#define KRB5_TMP_FILE           "KRB5.INI.TMP"

BOOL 
khm_krb5_get_temp_profile_file(LPSTR confname, UINT szConfname)
{
    GetTempPathA(szConfname, confname);
    confname[szConfname-1] = '\0';
    StringCchCatA(confname, szConfname, KRB5_TMP_FILE);
    confname[szConfname-1] = '\0';
    return FALSE;
}

BOOL 
khm_krb5_get_profile_file(LPSTR confname, UINT szConfname)
{
    char **configFile = NULL;
    if (pkrb5_get_default_config_files(&configFile)) 
    {
        GetWindowsDirectoryA(confname,szConfname);
        confname[szConfname-1] = '\0';
        strncat(confname, "\\",sizeof(confname)-strlen(confname));
        confname[szConfname-1] = '\0';
        strncat(confname, KRB5_FILE,sizeof(confname)-strlen(confname));
        confname[szConfname-1] = '\0';
        return FALSE;
    }
    
    *confname = 0;
    
    if (configFile)
    {
        strncpy(confname, *configFile, szConfname);
        pkrb5_free_config_files(configFile); 
    }
    
    if (!*confname)
    {
        GetWindowsDirectoryA(confname,szConfname);
        confname[szConfname-1] = '\0';
        strncat(confname, "\\",sizeof(confname)-strlen(confname));
        confname[szConfname-1] = '\0';
        strncat(confname, KRB5_FILE,sizeof(confname)-strlen(confname));
        confname[szConfname-1] = '\0';
    }
    
    return FALSE;
}

BOOL
khm_get_krb4_con_file(LPSTR confname, UINT szConfname)
{
    if (hKrb5 && !hKrb4) { // hold krb.con where krb5.ini is located
        CHAR krbConFile[MAX_PATH]="";
        LPSTR pFind;

        //strcpy(krbConFile, CLeashApp::m_krbv5_profile->first_file->filename);
        if (khm_krb5_get_profile_file(krbConFile, sizeof(krbConFile))) {
            GetWindowsDirectoryA(krbConFile,sizeof(krbConFile));
            krbConFile[MAX_PATH-1] = '\0';
            strncat(krbConFile, "\\",sizeof(krbConFile)-strlen(krbConFile));
            krbConFile[MAX_PATH-1] = '\0';
            strncat(krbConFile, KRB5_FILE,sizeof(krbConFile)-strlen(krbConFile));
            krbConFile[MAX_PATH-1] = '\0';
        }
        
        pFind = strrchr(krbConFile, '\\');
        if (pFind) {
            *pFind = 0;
            strncat(krbConFile, "\\",sizeof(krbConFile)-strlen(krbConFile));
            krbConFile[MAX_PATH-1] = '\0';
            strncat(krbConFile, KRB_FILE,sizeof(krbConFile)-strlen(krbConFile));
            krbConFile[MAX_PATH-1] = '\0';
        }
        else
            krbConFile[0] = 0;
        
        strncpy(confname, krbConFile, szConfname);
        confname[szConfname-1] = '\0';
    }
    else if (hKrb4) { 
        unsigned int size = szConfname;
        memset(confname, '\0', szConfname);
        if (!pkrb_get_krbconf2(confname, &size))
            { // Error has happened
                GetWindowsDirectoryA(confname,szConfname);
                confname[szConfname-1] = '\0';
                strncat(confname, "\\",szConfname-strlen(confname));
                confname[szConfname-1] = '\0';
                strncat(confname,KRB_FILE,szConfname-strlen(confname));
                confname[szConfname-1] = '\0';
            }
    }
    return FALSE;
}

int
readstring(FILE * file, char * buf, int len)
{
    int  c,i;
    memset(buf, '\0', sizeof(buf));
    for (i=0, c=fgetc(file); c != EOF ; c=fgetc(file), i++) {	
        if (i < sizeof(buf)) {
            if (c == '\n') {
                buf[i] = '\0';
                return i;
            } else {
                buf[i] = c;
            }
        } else {
            if (c == '\n') {
                buf[len-1] = '\0';
                return(i);
            }
        }
    }
    if (c == EOF) {
        if (i > 0 && i < len) {
            buf[i] = '\0';
            return(i);
        } else {
            buf[len-1] = '\0';
            return(-1);
        }
    }
    return(-1);
}

/*! \internal
    \brief Return a list of configured realms

    The string that is returned is a set of null terminated unicode
    strings, each of which denotes one realm.  The set is terminated
    by a zero length null terminated string.

    The caller should free the returned string using free()

    \return The string with the list of realms or NULL if the
    operation fails.
*/
wchar_t * 
khm_krb5_get_realm_list(void) 
{
    wchar_t * rlist = NULL;

    if (pprofile_get_subsection_names && pprofile_free_list) {
        const char*  rootSection[] = {"realms", NULL};
        const char** rootsec = rootSection;
        char **sections = NULL, **cpp = NULL, *value = NULL;

        char krb5_conf[MAX_PATH+1];

        if (!khm_krb5_get_profile_file(krb5_conf,sizeof(krb5_conf))) {
            profile_t profile;
            long retval;
            const char *filenames[2];
            wchar_t * d;
            size_t cbsize;
            size_t t;

            filenames[0] = krb5_conf;
            filenames[1] = NULL;
            retval = pprofile_init(filenames, &profile);
            if (!retval) {
                retval = pprofile_get_subsection_names(profile,	rootsec, 
                                                       &sections);

                if (!retval)
                    {
                    /* first figure out how much space to allocate */
                    cbsize = 0;
                    for (cpp = sections; *cpp; cpp++) 
                    {
                        cbsize += sizeof(wchar_t) * (strlen(*cpp) + 1);
                    }
                    cbsize += sizeof(wchar_t); /* double null terminated */

                    rlist = PMALLOC(cbsize);
                    d = rlist;
                    for (cpp = sections; *cpp; cpp++)
                    {
                        AnsiStrToUnicode(d, cbsize, *cpp);
                        t = wcslen(d) + 1;
                        d += t;
                        cbsize -= sizeof(wchar_t) * t;
                    }
                    *d = L'\0';
                }

                pprofile_free_list(sections);

#if 0
                retval = pprofile_get_string(profile, "libdefaults","noaddresses", 0, "true", &value);
                if ( value ) {
                    disable_noaddresses = config_boolean_to_int(value);
                    pprofile_release_string(value);
                }
#endif
                pprofile_release(profile);
            }
        }
    } else {
        FILE * file;
        char krb_conf[MAX_PATH+1];
        char * p;
        size_t cbsize, t;
        wchar_t * d;

        if (!khm_get_krb4_con_file(krb_conf,sizeof(krb_conf)) && 
            (file = fopen(krb_conf, "rt")))
        {
            char lineBuf[256];

            /*TODO: compute the actual required buffer size instead of hardcoding */
            cbsize = 16384; // arbitrary
            rlist = PMALLOC(cbsize);
            d = rlist;

            // Skip the default realm
            readstring(file,lineBuf,sizeof(lineBuf));

            // Read the defined realms
            while (TRUE)
            {
                if (readstring(file,lineBuf,sizeof(lineBuf)) < 0)
                    break;

                if (*(lineBuf + strlen(lineBuf) - 1) == '\r')
                    *(lineBuf + strlen(lineBuf) - 1) = 0;

                for (p=lineBuf; *p ; p++)
                {
                    if (isspace(*p)) {
                        *p = 0;
                        break;
                    }
                }

                if ( strncmp(".KERBEROS.OPTION.",lineBuf,17) ) {
                    t = strlen(lineBuf) + 1;
                    if(cbsize > (1 + t*sizeof(wchar_t))) {
                        AnsiStrToUnicode(d, cbsize, lineBuf);
                        d += t;
                        cbsize -= t * sizeof(wchar_t);
                    } else
                        break;
                }
            }

            *d = L'\0';

            fclose(file);
        }
    }

    return rlist;
}

/*! \internal
    \brief Get the default realm

    A string will be returned that specifies the default realm.  The
    caller should free the string using free().

    Returns NULL if the operation fails.
*/
wchar_t * 
khm_krb5_get_default_realm(void)
{
    wchar_t * realm;
    size_t cch;
    krb5_context ctx=0;
    char * def = 0;

    pkrb5_init_context(&ctx);
    pkrb5_get_default_realm(ctx,&def);
    
    if (def) {
        cch = strlen(def) + 1;
        realm = PMALLOC(sizeof(wchar_t) * cch);
        AnsiStrToUnicode(realm, sizeof(wchar_t) * cch, def);
        pkrb5_free_default_realm(ctx, def);
    } else
        realm = NULL;

    pkrb5_free_context(ctx);

    return realm;
}

long
khm_krb5_set_default_realm(wchar_t * realm) {
    krb5_context ctx=0;
    char * def = 0;
    long rv = 0;
    char astr[K5_MAXCCH_REALM];

    UnicodeStrToAnsi(astr, sizeof(astr), realm);

    pkrb5_init_context(&ctx);
    pkrb5_get_default_realm(ctx,&def);

    if ((def && strcmp(def, astr)) ||
        !def) {
        rv = pkrb5_set_default_realm(ctx, astr);
    }

    if (def) {
        pkrb5_free_default_realm(ctx, def);
    }

    pkrb5_free_context(ctx);

    return rv;
}

wchar_t * 
khm_get_realm_from_princ(wchar_t * princ) {
    wchar_t * t;

    if(!princ)
        return NULL;

    for (t = princ; *t; t++) {
        if(*t == L'\\') {       /* escape */
            t++;
            if(! *t)            /* malformed */
                break;
        } else if (*t == L'@')
            break;
    }

    if (*t == '@' && *(t+1) != L'\0')
        return (t+1);
    else
        return NULL;
}

long
khm_krb5_changepwd(char * principal,
                   char * password,
                   char * newpassword,
                   char** error_str)
{
    krb5_error_code rc = 0;
    int result_code;
    krb5_data result_code_string, result_string;
    krb5_context context = 0;
    krb5_principal princ = 0;
    krb5_get_init_creds_opt opts;
    krb5_creds creds;

    result_string.data = 0;
    result_code_string.data = 0;

    if ( !pkrb5_init_context )
        goto cleanup;

   if (rc = pkrb5_init_context(&context)) {
       goto cleanup;
   }

   if (rc = pkrb5_parse_name(context, principal, &princ)) {
       goto cleanup;
   }

   pkrb5_get_init_creds_opt_init(&opts);
   pkrb5_get_init_creds_opt_set_tkt_life(&opts, 5*60);
   pkrb5_get_init_creds_opt_set_renew_life(&opts, 0);
   pkrb5_get_init_creds_opt_set_forwardable(&opts, 0);
   pkrb5_get_init_creds_opt_set_proxiable(&opts, 0);
   pkrb5_get_init_creds_opt_set_address_list(&opts,NULL);

   if (rc = pkrb5_get_init_creds_password(context, &creds, princ, 
                                          password, 0, 0, 0, 
                                          "kadmin/changepw", &opts)) {
       if (rc == KRB5KRB_AP_ERR_BAD_INTEGRITY) {
#if 0
           com_err(argv[0], 0,
                   "Password incorrect while getting initial ticket");
#endif
       }
       else {
#if 0
           com_err(argv[0], ret, "getting initial ticket");
#endif
       }
       goto cleanup;
   }

   if (rc = pkrb5_change_password(context, &creds, newpassword,
                                  &result_code, &result_code_string,
                                  &result_string)) {
#if 0
       com_err(argv[0], ret, "changing password");
#endif
       goto cleanup;
   }

   if (result_code) {
       int len = result_code_string.length + 
           (result_string.length ? (sizeof(": ") - 1) : 0) +
           result_string.length;
       if (len && error_str) {
           *error_str = PMALLOC(len + 1);
           if (*error_str)
               StringCchPrintfA(*error_str, len+1,
                                "%.*s%s%.*s",
                                result_code_string.length, 
                                result_code_string.data,
                                result_string.length?": ":"",
                                result_string.length, 
                                result_string.data);
       }
       rc = result_code;
       goto cleanup;
   }

 cleanup:
   if (result_string.data)
       pkrb5_free_data_contents(context, &result_string);

   if (result_code_string.data)
       pkrb5_free_data_contents(context, &result_code_string);

   if (princ)
       pkrb5_free_principal(context, princ);

   if (context)
       pkrb5_free_context(context);

   return rc;
}

khm_int32 KHMAPI
khm_krb5_creds_is_equal(khm_handle vcred1, khm_handle vcred2, void * dummy) {
    if (kcdb_creds_comp_attr(vcred1, vcred2, KCDB_ATTR_LOCATION) ||
        kcdb_creds_comp_attr(vcred1, vcred2, attr_id_key_enctype) ||
        kcdb_creds_comp_attr(vcred1, vcred2, attr_id_tkt_enctype))
        return 1;
    else
        return 0;
}

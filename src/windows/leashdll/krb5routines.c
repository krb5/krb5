// Module name: krb5routines.c

#include <windows.h>
#define SECURITY_WIN32
#include <security.h>

/* _WIN32_WINNT must be 0x0501 or greater to pull in definition of
 * all required LSA data types when the Vista SDK NtSecAPI.h is used.
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#else
#if _WIN32_WINNT < 0x0501
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#endif
#include <ntsecapi.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <winsock2.h>

/* Private Include files */
#include "leashdll.h"
#include <leashwin.h>
#include "leash-int.h"

#define KRB5_DEFAULT_LIFE            60*60*10 /* 10 hours */

char *GetTicketFlag(krb5_creds *cred)
{
   static char buf[32];
   int i = 0;

   buf[i++] = ' ';
   buf[i++] = '(';

   if (cred->ticket_flags & TKT_FLG_FORWARDABLE)
     buf[i++] = 'F';

   if (cred->ticket_flags & TKT_FLG_FORWARDED)
     buf[i++] = 'f';

   if (cred->ticket_flags & TKT_FLG_PROXIABLE)
     buf[i++] = 'P';

   if (cred->ticket_flags & TKT_FLG_PROXY)
     buf[i++] = 'p';

   if (cred->ticket_flags & TKT_FLG_MAY_POSTDATE)
     buf[i++] = 'D';

   if (cred->ticket_flags & TKT_FLG_POSTDATED)
     buf[i++] = 'd';

   if (cred->ticket_flags & TKT_FLG_INVALID)
     buf[i++] = 'i';

   if (cred->ticket_flags & TKT_FLG_RENEWABLE)
     buf[i++] = 'R';

   if (cred->ticket_flags & TKT_FLG_INITIAL)
     buf[i++] = 'I';

   if (cred->ticket_flags & TKT_FLG_HW_AUTH)
     buf[i++] = 'H';

   if (cred->ticket_flags & TKT_FLG_PRE_AUTH)
     buf[i++] = 'A';

   buf[i++] = ')';
   buf[i] = '\0';

   if (i <= 3)
     buf[0] = '\0';

   return buf;
}

long
Leash_convert524(
     krb5_context alt_ctx
     )
{
#if defined(NO_KRB5) || defined(NO_KRB4)
    return(0);
#else
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

	v4creds = (CREDENTIALS *) malloc(sizeof(CREDENTIALS));
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
                                     NULL))) {
        goto cleanup;
    }

    increds.client = me;
    increds.server = server;
    increds.times.endtime = 0;
    increds.keyblock.enctype = ENCTYPE_DES_CBC_CRC;
    if ((code = pkrb5_get_credentials(ctx, 0,
                                     cc,
                                     &increds,
                                     &v5creds))) {
        goto cleanup;
    }

    if ((icode = pkrb524_convert_creds_kdc(ctx,
                                          v5creds,
                                          v4creds))) {
        goto cleanup;
    }

    /* initialize ticket cache */
    if ((icode = pkrb_in_tkt(v4creds->pname, v4creds->pinst, v4creds->realm)
         != KSUCCESS)) {
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
                                      v4creds->issue_date))) {
        goto cleanup;
    }

 cleanup:
    memset(v4creds, 0, sizeof(v4creds));
    free(v4creds);

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
#endif /* NO_KRB5 */
}

#ifndef ENCTYPE_LOCAL_RC4_MD4
#define ENCTYPE_LOCAL_RC4_MD4    0xFFFFFF80
#endif

static char *
etype_string(krb5_enctype enctype)
{
    static char buf[12];

    switch (enctype) {
    case ENCTYPE_NULL:
        return "NULL";
    case ENCTYPE_DES_CBC_CRC:
        return "DES-CBC-CRC";
    case ENCTYPE_DES_CBC_MD4:
        return "DES-CBC-MD4";
    case ENCTYPE_DES_CBC_MD5:
        return "DES-CBC-MD5";
    case ENCTYPE_DES_CBC_RAW:
        return "DES-CBC-RAW";
    case ENCTYPE_DES3_CBC_SHA:
        return "DES3-CBC-SHA";
    case ENCTYPE_DES3_CBC_RAW:
        return "DES3-CBC-RAW";
    case ENCTYPE_DES_HMAC_SHA1:
        return "DES-HMAC-SHA1";
    case ENCTYPE_DES3_CBC_SHA1:
        return "DES3-CBC-SHA1";
    case ENCTYPE_AES128_CTS_HMAC_SHA1_96:
        return "AES128_CTS-HMAC-SHA1_96";
    case ENCTYPE_AES256_CTS_HMAC_SHA1_96:
        return "AES256_CTS-HMAC-SHA1_96";
    case ENCTYPE_ARCFOUR_HMAC:
        return "RC4-HMAC-NT";
    case ENCTYPE_ARCFOUR_HMAC_EXP:
        return "RC4-HMAC-NT-EXP";
    case ENCTYPE_UNKNOWN:
        return "UNKNOWN";
#ifdef ENCTYPE_LOCAL_DES3_HMAC_SHA1
    case ENCTYPE_LOCAL_DES3_HMAC_SHA1:
        return "LOCAL-DES3-HMAC-SHA1";
#endif
#ifdef ENCTYPE_LOCAL_RC4_MD4
    case ENCTYPE_LOCAL_RC4_MD4:
        return "LOCAL-RC4-MD4";
#endif
    default:
        wsprintf(buf, "#%d", enctype);
        return buf;
    }
}

char *
one_addr(krb5_address *a)
{
    static char retstr[256];
    struct hostent *h;
    int no_resolve = 1;

    retstr[0] = '\0';

    if ((a->addrtype == ADDRTYPE_INET && a->length == 4)
#ifdef AF_INET6
        || (a->addrtype == ADDRTYPE_INET6 && a->length == 16)
#endif
        ) {
        int af = AF_INET;
#ifdef AF_INET6
        if (a->addrtype == ADDRTYPE_INET6)
            af = AF_INET6;
#endif
        if (!no_resolve) {
#ifdef HAVE_GETIPNODEBYADDR
            int err;
            h = getipnodebyaddr(a->contents, a->length, af, &err);
            if (h) {
                wsprintf(retstr, "%s", h->h_name);
                freehostent(h);
            }
#else
            h = gethostbyaddr(a->contents, a->length, af);
            if (h) {
                wsprintf(retstr,"%s", h->h_name);
            }
#endif
            if (h)
                return(retstr);
        }
        if (no_resolve || !h) {
#ifdef HAVE_INET_NTOP
            char buf[46];
            const char *name = inet_ntop(a->addrtype, a->contents, buf, sizeof(buf));
            if (name) {
                wsprintf(retstr,"%s", name);
                return;
            }
#else
            if (a->addrtype == ADDRTYPE_INET) {
                wsprintf(retstr,"%d.%d.%d.%d", a->contents[0], a->contents[1],
                       a->contents[2], a->contents[3]);
                return(retstr);
            }
#endif
        }
    }
    wsprintf(retstr,"unknown addr type %d", a->addrtype);
    return(retstr);
}

static void
CredToTicketInfo(krb5_creds KRBv5Credentials, TICKETINFO *ticketinfo)
{
    ticketinfo->issued = KRBv5Credentials.times.starttime;
    ticketinfo->valid_until = KRBv5Credentials.times.endtime;
    ticketinfo->renew_until =
        KRBv5Credentials.ticket_flags & TKT_FLG_RENEWABLE ?
        KRBv5Credentials.times.renew_till : 0;
    _tzset();
    if (ticketinfo->valid_until - time(0) <= 0L)
        ticketinfo->btickets = EXPD_TICKETS;
    else
        ticketinfo->btickets = GOOD_TICKETS;
}

static int
CredToTicketList(krb5_context ctx, krb5_creds KRBv5Credentials,
                 char *PrincipalName, TicketList ***ticketListTail)
{
    krb5_error_code code = 0;
    krb5_ticket *tkt=NULL;
    char *sServerName = NULL;
    char Buffer[256];
    char *ticketFlag;
    char *functionName = NULL;
    TicketList *list = NULL;

    functionName = "krb5_unparse_name()";
    code = (*pkrb5_unparse_name)(ctx, KRBv5Credentials.server, &sServerName);
    if (code)
        goto cleanup;

    if (!KRBv5Credentials.times.starttime)
        KRBv5Credentials.times.starttime = KRBv5Credentials.times.authtime;

    memset(Buffer, '\0', sizeof(Buffer));

    ticketFlag = GetTicketFlag(&KRBv5Credentials);

    // @fixme: calloc for ptr init
    list = calloc(1, sizeof(TicketList));
    if (list == NULL) {
        code = ENOMEM;
        functionName = "calloc()";
        goto cleanup;
    }
    list->service = strdup(sServerName);
    if (!list->service) {
        code = ENOMEM;
        functionName = "calloc()";
        goto cleanup;
    }
    list->issued = KRBv5Credentials.times.starttime;
    list->valid_until = KRBv5Credentials.times.endtime;
    if (KRBv5Credentials.ticket_flags & TKT_FLG_RENEWABLE)
        list->renew_until = KRBv5Credentials.times.renew_till;
    else
        list->renew_until = 0;

    if (!pkrb5_decode_ticket(&KRBv5Credentials.ticket, &tkt)) {
        wsprintf(Buffer, "Session Key: %s  Ticket: %s",
                 etype_string(KRBv5Credentials.keyblock.enctype),
                 etype_string(tkt->enc_part.enctype));
        pkrb5_free_ticket(ctx, tkt);
        tkt = NULL;
    } else {
        wsprintf(Buffer, "Session Key: %s",
                 etype_string(KRBv5Credentials.keyblock.enctype));
    }

    list->encTypes = calloc(1, strlen(Buffer)+1);
    if (list->encTypes == NULL) {
        functionName = "calloc()";
        code = ENOMEM;
        goto cleanup;
    }
    strcpy(list->encTypes, Buffer);

cleanup:
    if (code) {
        Leash_krb5_error(code, functionName, 0, &ctx, NULL);
        if (list != NULL) {
            not_an_API_LeashFreeTicketList(&list);
        }
    } else {
        **ticketListTail = list;
        *ticketListTail = &list->next;
    }

    if (sServerName != NULL)
        (*pkrb5_free_unparsed_name)(ctx, sServerName);

    return code;
}

int
do_ccache(krb5_context ctx,
          krb5_ccache cache,
          TICKETINFO ***ticketInfoTail)
{
    krb5_cc_cursor cur;
    krb5_creds creds;
    krb5_principal princ = NULL;
    krb5_flags flags;
    krb5_error_code code;
    char *defname = NULL;
    char *functionName = NULL;
    TicketList **ticketListTail;
    TICKETINFO *ticketinfo;

    flags = 0;                          /* turns off OPENCLOSE mode */
    code = pkrb5_cc_set_flags(ctx, cache, flags);
    if (code) {
        functionName = "krb5_cc_set_flags";
        goto cleanup;
    }
    code = pkrb5_cc_get_principal(ctx, cache, &princ);
    if (code) {
        functionName = "krb5_cc_get_principal";
        goto cleanup;
    }
    code = pkrb5_unparse_name(ctx, princ, &defname);
    if (code) {
        functionName = "krb5_unparse_name";
        goto cleanup;
    }
    code = pkrb5_cc_start_seq_get(ctx, cache, &cur);
    if (code) {
        functionName = "krb5_cc_start_seq_get";
        goto cleanup;
    }

    ticketinfo = calloc(1, sizeof(TICKETINFO));
    if (ticketinfo == NULL) {
        functionName = "calloc";
        code = ENOMEM;
        goto cleanup;
    }
    ticketinfo->next = NULL;
    ticketinfo->ticket_list = NULL;
    ticketinfo->principal = strdup(defname);
    if (ticketinfo->principal == NULL) {
        functionName = "strdup";
        code = ENOMEM;
        goto cleanup;
    }
    ticketinfo->ccache_name = strdup(pkrb5_cc_get_name(ctx, cache));
    if (ticketinfo->ccache_name == NULL) {
        functionName = "strdup";
        code = ENOMEM;
        goto cleanup;
    }
    **ticketInfoTail = ticketinfo;
    *ticketInfoTail = &ticketinfo->next;
    ticketListTail = &ticketinfo->ticket_list;
    while (!(code = pkrb5_cc_next_cred(ctx, cache, &cur, &creds))) {
        if (pkrb5_is_config_principal(ctx, creds.server))
            continue;
        CredToTicketList(ctx, creds, defname, &ticketListTail);
        CredToTicketInfo(creds, ticketinfo);
        pkrb5_free_cred_contents(ctx, &creds);
    }
    if (code == KRB5_CC_END) {
        code = pkrb5_cc_end_seq_get(ctx, cache, &cur);
        if (code) {
            functionName = "krb5_cc_end_seq_get";
            goto cleanup;
        }
        flags = KRB5_TC_OPENCLOSE;      /* turns on OPENCLOSE mode */
        code = pkrb5_cc_set_flags(ctx, cache, flags);
        if (code) {
            functionName = "krb5_cc_set_flags";
            goto cleanup;
        }
    } else {
        functionName = "krb5_cc_next_cred";
        goto cleanup;
    }
cleanup:
    if (code) {
        Leash_krb5_error(code, functionName, 0, NULL, NULL);
    }
    if (princ)
        pkrb5_free_principal(ctx, princ);
    if (defname)
        pkrb5_free_unparsed_name(ctx, defname);
    return code ? 1 : 0;
}


//
// Returns 0 for success, 1 for failure
//
int
do_all_ccaches(krb5_context ctx, TICKETINFO **ticketinfotail)
{
    krb5_error_code code;
    krb5_ccache cache;
    krb5_cccol_cursor cursor;
    int retval = 0;
    char *functionName = NULL;

    code = pkrb5_cccol_cursor_new(ctx, &cursor);
    if (code) {
        functionName = "krb5_cccol_cursor_new";
        goto cleanup;
    }
    retval = 0;
    while (!(code = pkrb5_cccol_cursor_next(ctx, cursor, &cache)) &&
           cache != NULL) {
        // Note that ticketList will be updated here to point to the tail
        // of the list but the caller of this function will remain with a
        // pointer to the head.
        do_ccache(ctx, cache, &ticketinfotail);
        pkrb5_cc_close(ctx, cache);
    }
    if (code)
         functionName = "krb5_cccol_cursor_next";
    pkrb5_cccol_cursor_free(ctx, &cursor);
cleanup:
    if (code) {
        Leash_krb5_error(code, functionName, 0, NULL, NULL);
    }
    return retval;
}

static void FreeTicketInfo(TICKETINFO *ticketinfo)
{
    if (ticketinfo->principal) {
        free(ticketinfo->principal);
        ticketinfo->principal = NULL;
    }
    if (ticketinfo->ccache_name) {
        free(ticketinfo->ccache_name);
        ticketinfo->ccache_name = NULL;
    }
    if (ticketinfo->ticket_list)
        not_an_API_LeashFreeTicketList(&ticketinfo->ticket_list);
}

long
not_an_API_LeashKRB5FreeTickets(TICKETINFO *ticketinfo)
{
    TICKETINFO *initial = ticketinfo; // @TEMP fixme
    TICKETINFO *next;
    while (ticketinfo != NULL) {
        next = ticketinfo->next;
        FreeTicketInfo(ticketinfo);
        // @TEMP fixme
        if (ticketinfo != initial) {
            free(ticketinfo);
        }
        ticketinfo = next;
    }
    return 0;
}


/*
 * LeashKRB5GetTickets() treats krbv5Context as an in/out variable.
 * If the caller does not provide a krb5_context, one will be allocated.
 * It is up to the caller to ensure that the context is eventually freed.
 * A context can be returned even if the function returns an error.
 */

long
not_an_API_LeashKRB5GetTickets(TICKETINFO *ticketinfo,
                               krb5_context *krbv5Context)
{
    krb5_error_code code;
    krb5_principal me = 0;
    krb5_context ctx = 0;
    krb5_ccache cache = 0;
    char *PrincipalName = NULL;

    code = Leash_krb5_initialize(krbv5Context);
    if (code)
        return code;

    ctx = *krbv5Context;

    // @TEMP fixme; shouldn't be necessary
    // save default principal name in ticketinfo
    if (ticketinfo != NULL) {
        ticketinfo->btickets = NO_TICKETS;
        ticketinfo->principal = NULL;
        ticketinfo->ccache_name = NULL;
        ticketinfo->next = NULL;
        ticketinfo->ticket_list = NULL;

        code = pkrb5_cc_default(ctx, &cache);
        if (code)
            goto cleanup;
        ticketinfo->ccache_name = strdup(pkrb5_cc_get_name(ctx, cache));
        if (ticketinfo->ccache_name == NULL) {
            code = ENOMEM;
            goto cleanup;
        }
        if (!pkrb5_cc_get_principal(ctx, cache, &me)) {
            code = (*pkrb5_unparse_name)(ctx, me, &PrincipalName);
            if (code)
                goto cleanup;
            if (PrincipalName) {
                ticketinfo->principal = strdup(PrincipalName);
                pkrb5_free_unparsed_name(ctx, PrincipalName);
            }
        }
    }

    do_all_ccaches(*krbv5Context, &ticketinfo->next);
    // @TEMP aggregate ticket info here?

cleanup:
    if (code)
        not_an_API_LeashKRB5FreeTickets(ticketinfo);
    if (cache)
        pkrb5_cc_close(ctx, cache);
    if (me)
        pkrb5_free_principal(ctx, me);
    return code;
}


int
LeashKRB5_renew(void)
{
#ifdef NO_KRB5
    return(0);
#else
    krb5_error_code		        code = 0;
    krb5_context		        ctx = 0;
    krb5_ccache			        cc = 0;
    krb5_principal		        me = 0;
    krb5_principal              server = 0;
    krb5_creds			        my_creds;
    krb5_data                   *realm = 0;

    if ( !pkrb5_init_context )
        goto cleanup;

	memset(&my_creds, 0, sizeof(krb5_creds));

    code = pkrb5_init_context(&ctx);
    if (code) goto cleanup;

    code = pkrb5_cc_default(ctx, &cc);
    if (code) goto cleanup;

    code = pkrb5_cc_get_principal(ctx, cc, &me);
    if (code) goto cleanup;

    realm = krb5_princ_realm(ctx, me);

    code = pkrb5_build_principal_ext(ctx, &server,
                                    realm->length,realm->data,
                                    KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
                                    realm->length,realm->data,
                                    0);
    if ( code ) goto cleanup;

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
            Leash_krb5_error(code, "krb5_get_renewed_creds()", 0, &ctx, &cc);
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
#endif /* NO_KRB5 */
}

#ifndef NO_KRB5
static krb5_error_code KRB5_CALLCONV
leash_krb5_prompter( krb5_context context,
					 void *data,
					 const char *name,
					 const char *banner,
					 int num_prompts,
					 krb5_prompt prompts[]);
#endif /* NO_KRB5 */

int
Leash_krb5_kinit(
krb5_context alt_ctx,
HWND hParent,
char *principal_name,
char *password,
krb5_deltat lifetime,
DWORD                       forwardable,
DWORD                       proxiable,
krb5_deltat                 renew_life,
DWORD                       addressless,
DWORD                       publicIP
)
{
#ifdef NO_KRB5
    return(0);
#else
    krb5_error_code		        code = 0;
    krb5_context		        ctx = 0;
    krb5_ccache			        cc = 0, defcache = 0;
    krb5_principal		        me = 0;
    char*                       name = 0;
    krb5_creds			        my_creds;
    krb5_get_init_creds_opt *   options = NULL;
    krb5_address **             addrs = NULL;
    int                         i = 0, addr_count = 0;
    int                         cc_new = 0;
    const char *                deftype = NULL;

    if (!pkrb5_init_context)
        return 0;

    memset(&my_creds, 0, sizeof(my_creds));

    if (alt_ctx)
    {
        ctx = alt_ctx;
    }
    else
    {
        code = pkrb5_init_context(&ctx);
        if (code) goto cleanup;
    }

    code = pkrb5_get_init_creds_opt_alloc(ctx, &options);
    if (code) goto cleanup;

    code = pkrb5_cc_default(ctx, &defcache);
    if (code) goto cleanup;

    code = pkrb5_parse_name(ctx, principal_name, &me);
    if (code) goto cleanup;

    deftype = pkrb5_cc_get_type(ctx, defcache);
    if (me != NULL && pkrb5_cc_support_switch(ctx, deftype)) {
        /* Use an existing cache for the specified principal if we can. */
        code = pkrb5_cc_cache_match(ctx, me, &cc);
        if (code != 0 && code != KRB5_CC_NOTFOUND)
            goto cleanup;
        if (code == KRB5_CC_NOTFOUND) {
            code = pkrb5_cc_new_unique(ctx, deftype, NULL, &cc);
            if (code)
                goto cleanup;
            cc_new = 1;
        }
        pkrb5_cc_close(ctx, defcache);
    } else {
        cc = defcache;
    }

    code = pkrb5_unparse_name(ctx, me, &name);
    if (code) goto cleanup;

    if (lifetime == 0)
        lifetime = Leash_get_default_lifetime();
    else
        lifetime *= 5*60;

	if (renew_life > 0)
		renew_life *= 5*60;

    if (lifetime)
        pkrb5_get_init_creds_opt_set_tkt_life(options, lifetime);
	pkrb5_get_init_creds_opt_set_forwardable(options,
                                             forwardable ? 1 : 0);
	pkrb5_get_init_creds_opt_set_proxiable(options,
                                           proxiable ? 1 : 0);
	pkrb5_get_init_creds_opt_set_renew_life(options,
                                            renew_life);
    if (addressless)
        pkrb5_get_init_creds_opt_set_address_list(options,NULL);
    else {
		if (publicIP)
        {
            // we are going to add the public IP address specified by the user
            // to the list provided by the operating system
            krb5_address ** local_addrs=NULL;
            DWORD           netIPAddr;

            pkrb5_os_localaddr(ctx, &local_addrs);
            while ( local_addrs[i++] );
            addr_count = i + 1;

            addrs = (krb5_address **) malloc((addr_count+1) * sizeof(krb5_address *));
            if ( !addrs ) {
                pkrb5_free_addresses(ctx, local_addrs);
                assert(0);
            }
            memset(addrs, 0, sizeof(krb5_address *) * (addr_count+1));
            i = 0;
            while ( local_addrs[i] ) {
                addrs[i] = (krb5_address *)malloc(sizeof(krb5_address));
                if (addrs[i] == NULL) {
                    pkrb5_free_addresses(ctx, local_addrs);
                    assert(0);
                }

                addrs[i]->magic = local_addrs[i]->magic;
                addrs[i]->addrtype = local_addrs[i]->addrtype;
                addrs[i]->length = local_addrs[i]->length;
                addrs[i]->contents = (unsigned char *)malloc(addrs[i]->length);
                if (!addrs[i]->contents) {
                    pkrb5_free_addresses(ctx, local_addrs);
                    assert(0);
                }

                memcpy(addrs[i]->contents,local_addrs[i]->contents,
                        local_addrs[i]->length);        /* safe */
                i++;
            }
            pkrb5_free_addresses(ctx, local_addrs);

            addrs[i] = (krb5_address *)malloc(sizeof(krb5_address));
            if (addrs[i] == NULL)
                assert(0);

            addrs[i]->magic = KV5M_ADDRESS;
            addrs[i]->addrtype = AF_INET;
            addrs[i]->length = 4;
            addrs[i]->contents = (unsigned char *)malloc(addrs[i]->length);
            if (!addrs[i]->contents)
                assert(0);

            netIPAddr = htonl(publicIP);
            memcpy(addrs[i]->contents,&netIPAddr,4);

            pkrb5_get_init_creds_opt_set_address_list(options,addrs);

        }
    }

    code = pkrb5_get_init_creds_opt_set_out_ccache(ctx, options, cc);
    if (code)
        goto cleanup;

    code = pkrb5_get_init_creds_password(ctx,
                                       &my_creds,
                                       me,
                                       password, // password
                                       leash_krb5_prompter, // prompter
                                       hParent, // prompter data
                                       0, // start time
                                       0, // service name
                                       options);
    // @TODO: make this an option
    if ((!code) && (cc != defcache)) {
        code = pkrb5_cc_switch(ctx, cc);
        if (!code) {
            const char *cctype = pkrb5_cc_get_type(ctx, cc);
            if (cctype != NULL) {
                char defname[20];
                sprintf_s(defname, sizeof(defname), "%s:", cctype);
                pkrb5int_cc_user_set_default_name(ctx, defname);
            }
        }
    }
 cleanup:
    if (code && cc_new) {
        // don't leave newly-generated empty ccache lying around on failure
        pkrb5_cc_destroy(ctx, cc);
        cc = NULL;
    }
    if ( addrs ) {
        for ( i=0;i<addr_count;i++ ) {
            if ( addrs[i] ) {
                if ( addrs[i]->contents )
                    free(addrs[i]->contents);
                free(addrs[i]);
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
    if (options)
        pkrb5_get_init_creds_opt_free(ctx, options);
    if (ctx && (ctx != alt_ctx))
	pkrb5_free_context(ctx);
    return(code);
#endif //!NO_KRB5
}


/**************************************/
/* LeashKRB5destroyTicket():          */
/**************************************/
int
Leash_krb5_kdestroy(
    void
    )
{
#ifdef NO_KRB5
    return(0);
#else
    krb5_context		ctx;
    krb5_ccache			cache;
    krb5_error_code		rc;

    ctx = NULL;
    cache = NULL;
    rc = Leash_krb5_initialize(&ctx);
    if (rc)
        return(rc);

    if (rc = pkrb5_cc_default(ctx, &cache))
        return(rc);

    rc = pkrb5_cc_destroy(ctx, cache);

    if (ctx != NULL)
        pkrb5_free_context(ctx);

    return(rc);

#endif //!NO_KRB5
}

krb5_error_code
Leash_krb5_cc_default(krb5_context *ctx, krb5_ccache *cache)
{
    krb5_error_code rc;
    krb5_flags flags;

    char *functionName = NULL;
    if (*cache == 0) {
        rc = pkrb5_cc_default(*ctx, cache);
        if (rc) {
            functionName = "krb5_cc_default()";
            goto on_error;
        }
    }
#ifdef KRB5_TC_NOTICKET
    flags = KRB5_TC_NOTICKET;
#endif
    rc = pkrb5_cc_set_flags(*ctx, *cache, flags);
    if (rc) {
        if (rc == KRB5_FCC_NOFILE || rc == KRB5_CC_NOTFOUND) {
            if (*cache != NULL && *ctx != NULL)
                pkrb5_cc_close(*ctx, *cache);
        } else {
            functionName = "krb5_cc_set_flags()";
            goto on_error;
        }
    }
on_error:
    if (rc && functionName) {
        Leash_krb5_error(rc, functionName, 0, ctx, cache);
    }
    return rc;
}

/**************************************/
/* Leash_krb5_initialize():             */
/**************************************/
int Leash_krb5_initialize(krb5_context *ctx)
{
#ifdef NO_KRB5
    return(0);
#else

    LPCSTR          functionName = NULL;
    krb5_error_code	rc;

    if (pkrb5_init_context == NULL)
        return 1;

    if (*ctx == 0) {
        if (rc = (*pkrb5_init_context)(ctx)) {
            functionName = "krb5_init_context()";
            return Leash_krb5_error(rc, functionName, 0, ctx, NULL);
        }
    }
    return 0;
#endif //!NO_KRB5
}


/**************************************/
/* Leash_krb5_error():           */
/**************************************/
int
Leash_krb5_error(krb5_error_code rc, LPCSTR FailedFunctionName,
                 int FreeContextFlag, krb5_context * ctx,
                 krb5_ccache * cache)
{
#ifdef NO_KRB5
    return 0;
#else
#ifdef USE_MESSAGE_BOX
    char message[256];
    const char *errText;

    errText = perror_message(rc);
    _snprintf(message, sizeof(message),
              "%s\n(Kerberos error %ld)\n\n%s failed",
              errText,
              rc,
              FailedFunctionName);
    message[sizeof(message)-1] = 0;

    MessageBox(NULL, message, "Kerberos Five", MB_OK | MB_ICONERROR |
               MB_TASKMODAL |
               MB_SETFOREGROUND);
#endif /* USE_MESSAGE_BOX */

    if (ctx != NULL && *ctx != NULL) {
        if (cache != NULL && *cache != NULL) {
            pkrb5_cc_close(*ctx, *cache);
            *cache = NULL;
        }

        if (FreeContextFlag) {
            pkrb5_free_context(*ctx);
            *ctx = NULL;
        }
    }

    return rc;

#endif //!NO_KRB5
}


BOOL
Leash_ms2mit(BOOL save_creds)
{
#ifdef NO_KRB5
    return(FALSE);
#else /* NO_KRB5 */
    krb5_context kcontext = 0;
    krb5_error_code code;
    krb5_ccache ccache=0;
    krb5_ccache mslsa_ccache=0;
    krb5_creds creds;
    krb5_cc_cursor cursor=0;
    krb5_principal princ = 0;
    BOOL rc = FALSE;

    if ( !pkrb5_init_context )
        goto cleanup;

    if (code = pkrb5_init_context(&kcontext))
        goto cleanup;

    if (code = pkrb5_cc_resolve(kcontext, "MSLSA:", &mslsa_ccache))
        goto cleanup;

    if ( save_creds ) {
        if (code = pkrb5_cc_get_principal(kcontext, mslsa_ccache, &princ))
            goto cleanup;

        if (code = pkrb5_cc_default(kcontext, &ccache))
            goto cleanup;

        if (code = pkrb5_cc_initialize(kcontext, ccache, princ))
            goto cleanup;

        if (code = pkrb5_cc_copy_creds(kcontext, mslsa_ccache, ccache))
            goto cleanup;

        rc = TRUE;
    } else {
        /* Enumerate tickets from cache looking for an initial ticket */
        if ((code = pkrb5_cc_start_seq_get(kcontext, mslsa_ccache, &cursor)))
            goto cleanup;

        while (!(code = pkrb5_cc_next_cred(kcontext, mslsa_ccache, &cursor, &creds)))
        {
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


#ifndef NO_KRB5
/* User Query data structures and functions */

struct textField {
    char * buf;                       /* Destination buffer address */
    int    len;                       /* Destination buffer length */
    char * label;                     /* Label for this field */
    char * def;                       /* Default response for this field */
    int    echo;                      /* 0 = no, 1 = yes, 2 = asterisks */
};

static int                mid_cnt = 0;
static struct textField * mid_tb = NULL;

#define ID_TEXT       150
#define ID_MID_TEXT 300

static BOOL CALLBACK
MultiInputDialogProc( HWND hDialog, UINT message, WPARAM wParam, LPARAM lParam)
{
    int i;

    switch ( message ) {
    case WM_INITDIALOG:
        if ( GetDlgCtrlID((HWND) wParam) != ID_MID_TEXT )
        {
            SetFocus(GetDlgItem( hDialog, ID_MID_TEXT));
            return FALSE;
        }
		for ( i=0; i < mid_cnt ; i++ ) {
			if (mid_tb[i].echo == 0)
				SendDlgItemMessage(hDialog, ID_MID_TEXT+i, EM_SETPASSWORDCHAR, 32, 0);
		    else if (mid_tb[i].echo == 2)
				SendDlgItemMessage(hDialog, ID_MID_TEXT+i, EM_SETPASSWORDCHAR, '*', 0);
		}
        return TRUE;

    case WM_COMMAND:
        switch ( LOWORD(wParam) ) {
        case IDOK:
            for ( i=0; i < mid_cnt ; i++ ) {
                if ( !GetDlgItemText(hDialog, ID_MID_TEXT+i, mid_tb[i].buf, mid_tb[i].len) )
                    *mid_tb[i].buf = '\0';
            }
            /* fallthrough */
        case IDCANCEL:
            EndDialog(hDialog, LOWORD(wParam));
            return TRUE;
        }
    }
    return FALSE;
}

static LPWORD
lpwAlign( LPWORD lpIn )
{
    ULONG ul;

    ul = (ULONG) lpIn;
    ul += 3;
    ul >>=2;
    ul <<=2;
    return (LPWORD) ul;;
}

/*
 * dialog widths are measured in 1/4 character widths
 * dialog height are measured in 1/8 character heights
 */

static LRESULT
MultiInputDialog( HINSTANCE hinst, HWND hwndOwner,
                  char * ptext[], int numlines, int width,
                  int tb_cnt, struct textField * tb)
{
    HGLOBAL hgbl;
    LPDLGTEMPLATE lpdt;
    LPDLGITEMTEMPLATE lpdit;
    LPWORD lpw;
    LPWSTR lpwsz;
    LRESULT ret;
    int nchar, i;
    size_t pwid;

    hgbl = GlobalAlloc(GMEM_ZEROINIT, 4096);
    if (!hgbl)
        return -1;

    mid_cnt = tb_cnt;
    mid_tb = tb;

    lpdt = (LPDLGTEMPLATE)GlobalLock(hgbl);

    // Define a dialog box.

    lpdt->style = WS_POPUP | WS_BORDER | WS_SYSMENU
                   | DS_MODALFRAME | WS_CAPTION | DS_CENTER
                   | DS_SETFOREGROUND | DS_3DLOOK
                   | DS_SHELLFONT | DS_NOFAILCREATE;
    lpdt->cdit = numlines + (2 * tb_cnt) + 2;  // number of controls
    lpdt->x  = 10;
    lpdt->y  = 10;
    lpdt->cx = 20 + width * 4;
    lpdt->cy = 20 + (numlines + tb_cnt + 4) * 14;

    lpw = (LPWORD) (lpdt + 1);
    *lpw++ = 0;   // no menu
    *lpw++ = 0;   // predefined dialog box class (by default)

    lpwsz = (LPWSTR) lpw;
    nchar = MultiByteToWideChar (CP_ACP, 0, "", -1, lpwsz, 128);
    lpw   += nchar;
    *lpw++ = 8;                        // font size (points)
    lpwsz = (LPWSTR) lpw;
    nchar = MultiByteToWideChar (CP_ACP, 0, "MS Shell Dlg",
                                    -1, lpwsz, 128);
    lpw   += nchar;

    //-----------------------
    // Define an OK button.
    //-----------------------
    lpw = lpwAlign (lpw); // align DLGITEMTEMPLATE on DWORD boundary
    lpdit = (LPDLGITEMTEMPLATE) lpw;
    lpdit->style = WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP | WS_BORDER;
    lpdit->dwExtendedStyle = 0;
    lpdit->x  = (lpdt->cx - 14)/4 - 20;
    lpdit->y  = 10 + (numlines + tb_cnt + 2) * 14;
    lpdit->cx = 40;
    lpdit->cy = 14;
    lpdit->id = IDOK;  // OK button identifier

    lpw = (LPWORD) (lpdit + 1);
    *lpw++ = 0xFFFF;
    *lpw++ = 0x0080;    // button class

    lpwsz = (LPWSTR) lpw;
    nchar = MultiByteToWideChar (CP_ACP, 0, "OK", -1, lpwsz, 50);
    lpw   += nchar;
    *lpw++ = 0;           // no creation data

    //-----------------------
    // Define an Cancel button.
    //-----------------------
    lpw = lpwAlign (lpw); // align DLGITEMTEMPLATE on DWORD boundary
    lpdit = (LPDLGITEMTEMPLATE) lpw;
    lpdit->style = WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP | WS_BORDER;
    lpdit->dwExtendedStyle = 0;
    lpdit->x  = (lpdt->cx - 14)*3/4 - 20;
    lpdit->y  = 10 + (numlines + tb_cnt + 2) * 14;
    lpdit->cx = 40;
    lpdit->cy = 14;
    lpdit->id = IDCANCEL;  // CANCEL button identifier

    lpw = (LPWORD) (lpdit + 1);
    *lpw++ = 0xFFFF;
    *lpw++ = 0x0080;    // button class

    lpwsz = (LPWSTR) lpw;
    nchar = MultiByteToWideChar (CP_ACP, 0, "Cancel", -1, lpwsz, 50);
    lpw   += nchar;
    *lpw++ = 0;           // no creation data

    /* Add controls for preface data */
    for ( i=0; i<numlines; i++) {
        /*-----------------------
         * Define a static text control.
         *-----------------------*/
        lpw = lpwAlign (lpw); /* align DLGITEMTEMPLATE on DWORD boundary */
        lpdit = (LPDLGITEMTEMPLATE) lpw;
        lpdit->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
        lpdit->dwExtendedStyle = 0;
        lpdit->x  = 10;
        lpdit->y  = 10 + i * 14;
        lpdit->cx = strlen(ptext[i]) * 4 + 10;
        lpdit->cy = 14;
        lpdit->id = ID_TEXT + i;  // text identifier

        lpw = (LPWORD) (lpdit + 1);
        *lpw++ = 0xFFFF;
        *lpw++ = 0x0082;                         // static class

        lpwsz = (LPWSTR) lpw;
        nchar = MultiByteToWideChar (CP_ACP, 0, ptext[i],
                                         -1, lpwsz, 2*width);
        lpw   += nchar;
        *lpw++ = 0;           // no creation data
    }

    for ( i=0, pwid = 0; i<tb_cnt; i++) {
        if ( pwid < strlen(tb[i].label) )
            pwid = strlen(tb[i].label);
    }

    for ( i=0; i<tb_cnt; i++) {
        /* Prompt */
        /*-----------------------
         * Define a static text control.
         *-----------------------*/
        lpw = lpwAlign (lpw); /* align DLGITEMTEMPLATE on DWORD boundary */
        lpdit = (LPDLGITEMTEMPLATE) lpw;
        lpdit->style = WS_CHILD | WS_VISIBLE | SS_LEFT;
        lpdit->dwExtendedStyle = 0;
        lpdit->x  = 10;
        lpdit->y  = 10 + (numlines + i + 1) * 14;
        lpdit->cx = pwid * 4;
        lpdit->cy = 14;
        lpdit->id = ID_TEXT + numlines + i;  // text identifier

        lpw = (LPWORD) (lpdit + 1);
        *lpw++ = 0xFFFF;
        *lpw++ = 0x0082;                         // static class

        lpwsz = (LPWSTR) lpw;
        nchar = MultiByteToWideChar (CP_ACP, 0, tb[i].label ? tb[i].label : "",
                                     -1, lpwsz, 128);
        lpw   += nchar;
        *lpw++ = 0;           // no creation data

        /*-----------------------
         * Define an edit control.
         *-----------------------*/
        lpw = lpwAlign (lpw); /* align DLGITEMTEMPLATE on DWORD boundary */
        lpdit = (LPDLGITEMTEMPLATE) lpw;
        lpdit->style = WS_CHILD | WS_VISIBLE | ES_LEFT | WS_TABSTOP | WS_BORDER | (tb[i].echo == 1 ? 0L : ES_PASSWORD);
        lpdit->dwExtendedStyle = 0;
        lpdit->x  = 10 + (pwid + 1) * 4;
        lpdit->y  = 10 + (numlines + i + 1) * 14;
        lpdit->cx = (width - (pwid + 1)) * 4;
        lpdit->cy = 14;
        lpdit->id = ID_MID_TEXT + i;             // identifier

        lpw = (LPWORD) (lpdit + 1);
        *lpw++ = 0xFFFF;
        *lpw++ = 0x0081;                         // edit class

        lpwsz = (LPWSTR) lpw;
        nchar = MultiByteToWideChar (CP_ACP, 0, tb[i].def ? tb[i].def : "",
                                     -1, lpwsz, 128);
        lpw   += nchar;
        *lpw++ = 0;           // no creation data
    }

    GlobalUnlock(hgbl);
    ret = DialogBoxIndirect(hinst, (LPDLGTEMPLATE) hgbl,
							hwndOwner, (DLGPROC) MultiInputDialogProc);
    GlobalFree(hgbl);

    switch ( ret ) {
    case 0:     /* Timeout */
        return -1;
    case IDOK:
        return 1;
    case IDCANCEL:
        return 0;
    default: {
        char buf[256];
        sprintf(buf,"DialogBoxIndirect() failed: %d",GetLastError());
        MessageBox(hwndOwner,
                    buf,
                    "GetLastError()",
                    MB_OK | MB_ICONINFORMATION | MB_TASKMODAL);
        return -1;
    }
    }
}

static int
multi_field_dialog(HWND hParent, char * preface, int n, struct textField tb[])
{
	extern HINSTANCE hLeashInst;
    size_t maxwidth = 0;
    int numlines = 0;
    size_t len;
    char * plines[16], *p = preface ? preface : "";
    int i;

    for ( i=0; i<16; i++ )
        plines[i] = NULL;

    while (*p && numlines < 16) {
        plines[numlines++] = p;
        for ( ;*p && *p != '\r' && *p != '\n'; p++ );
        if ( *p == '\r' && *(p+1) == '\n' ) {
            *p++ = '\0';
            p++;
        } else if ( *p == '\n' ) {
            *p++ = '\0';
        }
        if ( strlen(plines[numlines-1]) > maxwidth )
            maxwidth = strlen(plines[numlines-1]);
    }

    for ( i=0;i<n;i++ ) {
        len = strlen(tb[i].label) + 1 + (tb[i].len > 40 ? 40 : tb[i].len);
        if ( maxwidth < len )
            maxwidth = len;
    }

    return(MultiInputDialog(hLeashInst, hParent, plines, numlines, maxwidth, n, tb));
}

static krb5_error_code KRB5_CALLCONV
leash_krb5_prompter( krb5_context context,
					 void *data,
					 const char *name,
					 const char *banner,
					 int num_prompts,
					 krb5_prompt prompts[])
{
    krb5_error_code     errcode = 0;
    int                 i;
    struct textField * tb = NULL;
    int    len = 0, blen=0, nlen=0;
	HWND hParent = (HWND)data;

    if (name)
        nlen = strlen(name)+2;

    if (banner)
        blen = strlen(banner)+2;

    tb = (struct textField *) malloc(sizeof(struct textField) * num_prompts);
    if ( tb != NULL ) {
        int ok;
        memset(tb,0,sizeof(struct textField) * num_prompts);
        for ( i=0; i < num_prompts; i++ ) {
            tb[i].buf = prompts[i].reply->data;
            tb[i].len = prompts[i].reply->length;
            tb[i].label = prompts[i].prompt;
            tb[i].def = NULL;
            tb[i].echo = (prompts[i].hidden ? 2 : 1);
        }

        ok = multi_field_dialog(hParent,(char *)banner,num_prompts,tb);
        if ( ok ) {
            for ( i=0; i < num_prompts; i++ )
                prompts[i].reply->length = strlen(prompts[i].reply->data);
        } else
            errcode = -2;
    }

    if ( tb )
        free(tb);
    if (errcode) {
        for (i = 0; i < num_prompts; i++) {
            memset(prompts[i].reply->data, 0, prompts[i].reply->length);
        }
    }
    return errcode;
}
#endif /* NO_KRB5 */

/*
 * Copyright (c) 2004 Massachusetts Institute of Technology
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

#include <windows.h>
#include <stdio.h>
#include <sys/types.h>
#include <winsock.h>
#include "leashdll.h"
#include <KerberosIV/krb.h>
#include <prot.h>
#include <time.h>

#include <leashwin.h>
#include "leasherr.h"
#include "leash-int.h"
#include "leashids.h"

#include <mitwhich.h>

#include <winkrbid.h>
#include "reminder.h"

static char FAR *err_context;

char KRB_HelpFile[_MAX_PATH] =	HELPFILE;

#define LEN     64                /* Maximum Hostname Length */

#define LIFE    DEFAULT_TKT_LIFE  /* lifetime of ticket in 5-minute units */

char *
short_date(dp)
    long   *dp;
{
    register char *cp;
    cp = ctime(dp) + 4; // skip day of week
    // cp[15] = '\0';
    cp[12] = '\0'; // Don't display seconds
    return (cp);
}


static
char*
clean_string(
    char* s
    )
{
    char* p = s;
    char* b = s;

    if (!s) return s;

    for (p = s; *p; p++) {
        switch (*p) {
        case '\007':
            /* Add more cases here */
            break;
        default:
            *b = *p;
            b++;
        }
    }
    *b = *p;
    return s;
}

static
int
leash_error_message(
    const char *error,
    int rcL,
    int rc4,
    int rc5,
    int rcA,
    char* result_string,
    int  displayMB
    )
{
    char message[2048];
    char *p = message;
    int size = sizeof(message);
    int n;

    // XXX: ignore AFS for now.

    if (!rc5 && !rc4 && !rcL)
        return 0;

    n = _snprintf(p, size, "%s\n\n", error);
    p += n;
    size -= n;

    if (rc5 && !result_string)
    {
        n = _snprintf(p, size,
                      "Kerberos 5: %s (error %ld)\n",
                      perror_message(rc5),
                      rc5 & 255 // XXX: & 255??!!!
            );
        p += n;
        size -= n;
    }
    if (rc4 && !result_string)
    {
        char buffer[1024];
        n = _snprintf(p, size,
                      "Kerberos 4: %s\n",
                      err_describe(buffer, rc4)
            );
        p += n;
        size -= n;
    }
    if (rcL)
    {
        char buffer[1024];
        n = _snprintf(p, size,
                      "\n%s\n",
                      err_describe(buffer, rcL)
            );
        p += n;
        size -= n;
    }
    if (result_string)
    {
        n = _snprintf(p, size,
                      "%s\n",
                      result_string);
        p += n;
        size -= n;
    }
    if ( displayMB )
        MessageBox(NULL, message, "Leash", MB_OK | MB_ICONERROR | MB_TASKMODAL | 
                    MB_SETFOREGROUND);

    if (rc5) return rc5;
    if (rc4) return rc4;
    if (rcL) return rcL;
    return 0;
}


static
char *
make_postfix(
    const char * base,
    const char * postfix,
    char ** rcopy
    )
{
    int base_size;
    int ret_size;
    char * copy = 0;
    char * ret = 0;

    base_size = strlen(base) + 1;
    ret_size = base_size + strlen(postfix) + 1;
    copy = malloc(base_size);
    ret = malloc(ret_size);

    if (!copy || !ret)
        goto cleanup;

    strncpy(copy, base, base_size);
    copy[base_size - 1] = 0;

    strncpy(ret, base, base_size);
    strncpy(ret + (base_size - 1), postfix, ret_size - (base_size - 1));
    ret[ret_size - 1] = 0;

 cleanup:
    if (!copy || !ret) {
        if (copy)
            free(copy);
        if (ret)
            free(ret);
        copy = ret = 0;
    }
    // INVARIANT: (ret ==> copy) && (copy ==> ret)
    *rcopy = copy;
    return ret;
}

static
long
make_temp_cache_v4(
    const char * postfix
    )
{
    static char * old_cache = 0;

    if (!pkrb_set_tkt_string || !ptkt_string || !pdest_tkt)
        return 0; // XXX - is this appropriate?

    if (old_cache) {
        pdest_tkt();
        pkrb_set_tkt_string(old_cache);
        free(old_cache);
        old_cache = 0;
    }

    if (postfix)
    {
        char * tmp_cache = make_postfix(ptkt_string(), postfix, &old_cache);

        if (!tmp_cache)
            return KFAILURE;

        pkrb_set_tkt_string(tmp_cache);
        free(tmp_cache);
    }
    return 0;
}

static
long
make_temp_cache_v5(
    const char * postfix,
    krb5_context * pctx
    )
{
    static krb5_context ctx = 0;
    static char * old_cache = 0;

    // INVARIANT: old_cache ==> ctx && ctx ==> old_cache

    if (pctx)
        *pctx = 0;

    if (!pkrb5_init_context || !pkrb5_free_context || !pkrb5_cc_resolve ||
        !pkrb5_cc_default_name || !pkrb5_cc_set_default_name)
        return 0;

    if (old_cache) {
        krb5_ccache cc = 0;
        if (!pkrb5_cc_resolve(ctx, pkrb5_cc_default_name(ctx), &cc))
            pkrb5_cc_destroy(ctx, cc);
        pkrb5_cc_set_default_name(ctx, old_cache);
        free(old_cache);
        old_cache = 0;
    }
    if (ctx) {
        pkrb5_free_context(ctx);
        ctx = 0;
    }

    if (postfix)
    {
        char * tmp_cache = 0;
        krb5_error_code rc = 0;

        rc = pkrb5_init_context(&ctx);
        if (rc) goto cleanup;

        tmp_cache = make_postfix(pkrb5_cc_default_name(ctx), postfix, 
                                 &old_cache);

        if (!tmp_cache) {
            rc = ENOMEM;
            goto cleanup;
        }

        rc = pkrb5_cc_set_default_name(ctx, tmp_cache);

    cleanup:
        if (rc && ctx) {
            pkrb5_free_context(ctx);
            ctx = 0;
        }
        if (tmp_cache)
            free(tmp_cache);
        if (pctx)
            *pctx = ctx;
        return rc;
    }
    return 0;
}

long
Leash_checkpwd(
    char *principal, 
    char *password
    )
{
    return Leash_int_checkpwd(principal, password, 0);
}

long 
Leash_int_checkpwd(
    char * principal,
    char * password,
    int    displayErrors
    )
{
    long rc = 0;
	krb5_context ctx = 0;	// statically allocated in make_temp_cache_v5
    // XXX - we ignore errors in make_temp_cache_v?  This is BAD!!!
    make_temp_cache_v4("_checkpwd");
    make_temp_cache_v5("_checkpwd", &ctx);
    rc = Leash_int_kinit_ex( ctx, 0,
                             principal, password, 0, 0, 0, 0,
                             Leash_get_default_noaddresses(),
                             Leash_get_default_publicip(),
                             displayErrors
                             );
    make_temp_cache_v4(0);
    make_temp_cache_v5(0, &ctx);
    return rc;
}

static
long
Leash_changepwd_v5(char * principal,
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
    DWORD addressless = 0;

    result_string.data = 0;
    result_code_string.data = 0;

    if ( !pkrb5_init_context )
        goto cleanup;

   if (rc = pkrb5_init_context(&context)) {
#if 0
       com_err(argv[0], ret, "initializing kerberos library");
#endif
       goto cleanup;
   }

   if (rc = pkrb5_parse_name(context, principal, &princ)) {
#if 0
       com_err(argv[0], ret, "parsing client name");
#endif
       goto cleanup;
   }

   pkrb5_get_init_creds_opt_init(&opts);
   pkrb5_get_init_creds_opt_set_tkt_life(&opts, 5*60);
   pkrb5_get_init_creds_opt_set_renew_life(&opts, 0);
   pkrb5_get_init_creds_opt_set_forwardable(&opts, 0);
   pkrb5_get_init_creds_opt_set_proxiable(&opts, 0);

   addressless = Leash_get_default_noaddresses();
   if (addressless)
       pkrb5_get_init_creds_opt_set_address_list(&opts,NULL);


   if (rc = pkrb5_get_init_creds_password(context, &creds, princ, password,
                                          0, 0, 0, "kadmin/changepw", &opts)) {
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
           *error_str = malloc(len + 1);
           if (*error_str)
               _snprintf(*error_str, len + 1,
                         "%.*s%s%.*s",
                         result_code_string.length, result_code_string.data,
                         result_string.length?": ":"",
                         result_string.length, result_string.data);
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

static
long
Leash_changepwd_v4(
    char * principal,
    char * password,
    char * newpassword,
    char** error_str
    )
{
    long k_errno;

    if (!pkrb_set_tkt_string || !ptkt_string || !pkadm_change_your_password ||
        !pdest_tkt)
        return KFAILURE;

    k_errno = make_temp_cache_v4("_chgpwd");
    if (k_errno) return k_errno;
    k_errno = pkadm_change_your_password(principal, password, newpassword, 
                                         error_str);
    make_temp_cache_v4(0);
    return k_errno;
}

/*
 * Leash_changepwd
 *
 * Try to change the password using one of krb5 or krb4 -- whichever one
 * works.  We return ok on the first one that works.
 */
long
Leash_changepwd(
    char * principal, 
    char * password, 
    char * newpassword,
    char** result_string
    )
{
    return Leash_int_changepwd(principal, password, newpassword, result_string, 0);
}

long
Leash_int_changepwd(
    char * principal, 
    char * password, 
    char * newpassword,
    char** result_string,
    int    displayErrors
    )
{
    char* v5_error_str = 0;
    char* v4_error_str = 0;
    char* error_str = 0;
    int rc4 = 0;
    int rc5 = 0;
    int rc = 0;
    if (hKrb5)
        rc = rc5 = Leash_changepwd_v5(principal, password, newpassword,
                                      &v5_error_str);
    if (hKrb4 && 
		Leash_get_default_use_krb4() &&
	    (!hKrb5 || rc5))
        rc = rc4 = Leash_changepwd_v4(principal, password, newpassword, 
                                      &v4_error_str);
    if (!rc)
        return 0;
    if (v5_error_str || v4_error_str) {
        int len = 0;
        char v5_prefix[] = "Kerberos 5: ";
        char sep[] = "\n";
        char v4_prefix[] = "Kerberos 4: ";

        clean_string(v5_error_str);
        clean_string(v4_error_str);

        if (v5_error_str)
            len += sizeof(sep) + sizeof(v5_prefix) + strlen(v5_error_str) + 
                sizeof(sep);
        if (v4_error_str)
            len += sizeof(sep) + sizeof(v4_prefix) + strlen(v4_error_str) + 
                sizeof(sep);
        error_str = malloc(len + 1);
        if (error_str) {
            char* p = error_str;
            int size = len + 1;
            int n;
            if (v5_error_str) {
                n = _snprintf(p, size, "%s%s%s%s",
                              sep, v5_prefix, v5_error_str, sep);
                p += n;
                size -= n;
            }
            if (v4_error_str) {
                n = _snprintf(p, size, "%s%s%s%s",
                              sep, v4_prefix, v4_error_str, sep);
                p += n;
                size -= n;
            }
            if (result_string)
                *result_string = error_str;
        }
    }
    return leash_error_message("Error while changing password.", 
                               rc4, rc4, rc5, 0, error_str, 
                               displayErrors
                               );
}

int (*Lcom_err)(LPSTR,long,LPSTR,...);
LPSTR (*Lerror_message)(long);
LPSTR (*Lerror_table_name)(long);


long
Leash_kinit(
    char * principal,
    char * password,
    int lifetime
    )
{
    return Leash_int_kinit_ex( 0, 0,
                               principal, 
                               password, 
                               lifetime,
                               Leash_get_default_forwardable(),
                               Leash_get_default_proxiable(),
                               Leash_get_default_renew_till(),
                               Leash_get_default_noaddresses(),
                               Leash_get_default_publicip(),
                               0
                               );
}

long
Leash_kinit_ex(
    char * principal, 
    char * password, 
    int lifetime,
    int forwardable,
    int proxiable,
    int renew_life,
    int addressless,
    unsigned long publicip
    )
{
    return Leash_int_kinit_ex( 0, /* krb5 context */
                               0, /* parent window */
                               principal, 
                               password, 
                               lifetime,
                               forwardable,
                               proxiable,
                               renew_life,
                               addressless,
                               publicip,
                               0
                               );
}

long
Leash_int_kinit_ex(
    krb5_context ctx,
    HWND hParent,
    char * principal, 
    char * password, 
    int lifetime,
    int forwardable,
    int proxiable,
    int renew_life,
    int addressless,
    unsigned long publicip,
    int displayErrors
    )
{
    LPCSTR  functionName; 
    char    aname[ANAME_SZ];
    char    inst[INST_SZ];
    char    realm[REALM_SZ];
    char    first_part[256];
    char    second_part[256];
    char    temp[1024];
    int     count;
    int     i;
    int rc4 = 0;
    int rc5 = 0;
    int rcA = 0;
    int rcL = 0;

    if (lifetime < 5)
        lifetime = 1;
    else
        lifetime /= 5;

	if (renew_life > 0 && renew_life < 5)
		renew_life = 1;
	else
		renew_life /= 5;

    /* This should be changed if the maximum ticket lifetime */
    /* changes */

    if (lifetime > 255)
        lifetime = 255;

    err_context = "parsing principal";

    memset(temp, '\0', sizeof(temp));
    memset(inst, '\0', sizeof(inst));
    memset(realm, '\0', sizeof(realm));
    memset(first_part, '\0', sizeof(first_part));
    memset(second_part, '\0', sizeof(second_part));

    sscanf(principal, "%[/0-9a-zA-Z._-]@%[/0-9a-zA-Z._-]", first_part, second_part);
    strcpy(temp, first_part);
    strcpy(realm, second_part);
    memset(first_part, '\0', sizeof(first_part));
    memset(second_part, '\0', sizeof(second_part));
    if (sscanf(temp, "%[@0-9a-zA-Z._-]/%[@0-9a-zA-Z._-]", first_part, second_part) == 2)
    {
        strcpy(aname, first_part);
        strcpy(inst, second_part);
    }
    else
    {
        count = 0;
        i = 0;
        for (i = 0; temp[i]; i++)
        {
            if (temp[i] == '.')
                ++count;
        }
        if (count > 1)
        {
            strcpy(aname, temp);
        }
        else
        {
            if (pkname_parse != NULL)
            {
                memset(first_part, '\0', sizeof(first_part));
                memset(second_part, '\0', sizeof(second_part));
                sscanf(temp, "%[@/0-9a-zA-Z_-].%[@/0-9a-zA-Z_-]", first_part, second_part);
                strcpy(aname, first_part);
                strcpy(inst, second_part);
            }
            else
            {
                strcpy(aname, temp);
            }
        }
    }

    memset(temp, '\0', sizeof(temp));
    strcpy(temp, aname);
    if (strlen(inst) != 0)
    {
        strcat(temp, "/");
        strcat(temp, inst);
    }
    if (strlen(realm) != 0)
    {
        strcat(temp, "@");
        strcat(temp, realm);
    }

    rc5 = Leash_krb5_kinit(ctx, hParent, 
							temp, password, lifetime,
							forwardable,
							proxiable,
							renew_life,
							addressless,
							publicip
							);
	if ( Leash_get_default_use_krb4() ) {
		if ( !rc5 ) {
            if (!Leash_convert524(ctx))
                rc4 = KFAILURE;
		} else {
			if (pkname_parse == NULL)
			{
				goto cleanup;
			}

			err_context = "getting realm";
			if (!*realm && (rc4  = (int)(*pkrb_get_lrealm)(realm, 1))) 
			{
				functionName = "krb_get_lrealm()";
				rcL  = LSH_FAILEDREALM;
				goto cleanup;
			}

			err_context = "checking principal";
			if ((!*aname) || (!(rc4  = (int)(*pk_isname)(aname))))
			{
				functionName = "krb_get_lrealm()";
				rcL = LSH_INVPRINCIPAL;
				goto cleanup;
			}

			/* optional instance */
			if (!(rc4 = (int)(*pk_isinst)(inst)))
			{
				functionName = "k_isinst()";
				rcL = LSH_INVINSTANCE;
				goto cleanup;
			}

			if (!(rc4 = (int)(*pk_isrealm)(realm)))
			{
				functionName = "k_isrealm()";
				rcL = LSH_INVREALM;
				goto cleanup;
			}

			err_context = "fetching ticket";	
			rc4 = (*pkrb_get_pw_in_tkt)(aname, inst, realm, "krbtgt", realm, 
											   lifetime, password);
			if (rc4) /* XXX: do we want: && (rc != NO_TKT_FIL) as well? */
			{ 
				functionName = "krb_get_pw_in_tkt()";
				rcL = KRBERR(rc4);
				goto cleanup;
			}
		}
	}

#ifndef NO_AFS
    if ( !rc5 || (Leash_get_default_use_krb4() && !rc4) ) {
        char c;
        char *r;
        char *t;
        for ( r=realm, t=temp; c=*r; r++,t++ )
            *t = isupper(c) ? tolower(c) : c;
        *t = '\0';

        rcA = Leash_afs_klog("afs", temp, realm, lifetime);
        if (rcA)
            rcA = Leash_afs_klog("afs", "", realm, lifetime);
    }
#endif /* NO_AFS */

 cleanup:
    return leash_error_message("Ticket initialization failed.", 
                               rcL, (rc5 && rc4)?KRBERR(rc4):0, rc5, rcA, 0,
                               displayErrors);
}

long FAR
Leash_renew(void)
{
    if ( hKrb5 && !LeashKRB5_renew() ) {
        int lifetime;
        lifetime = Leash_get_default_lifetime() / 5;
		if (hKrb4 && Leash_get_default_use_krb4())
			Leash_convert524(0);
#ifndef NO_AFS
        {
            TicketList * list = NULL, * token;
            afs_get_tokens(NULL,&list,NULL);
            for ( token = list ; token ; token = token->next )
                Leash_afs_klog("afs", token->realm, "", lifetime);
            not_an_API_LeashFreeTicketList(&list);
        }
#endif /* NO_AFS */
        return 1;
    }
    return 0;
}

static BOOL
GetSecurityLogonSessionData(PSECURITY_LOGON_SESSION_DATA * ppSessionData)
{
    NTSTATUS Status = 0;
    HANDLE  TokenHandle;
    TOKEN_STATISTICS Stats;
    DWORD   ReqLen;
    BOOL    Success;

    if (!ppSessionData || !pLsaGetLogonSessionData)
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

// IsKerberosLogon() does not validate whether or not there are valid tickets in the 
// cache.  It validates whether or not it is reasonable to assume that if we 
// attempted to retrieve valid tickets we could do so.  Microsoft does not 
// automatically renew expired tickets.  Therefore, the cache could contain
// expired or invalid tickets.  Microsoft also caches the user's password 
// and will use it to retrieve new TGTs if the cache is empty and tickets
// are requested.

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
                lstrcpyn (buffer, usBuffer, usLength);
                lstrcat (buffer,L"");
                if ( !lstrcmp(L"Kerberos",buffer) )
                    Success = TRUE;
            }
        }
        pLsaFreeReturnBuffer(pSessionData);
    }
    return Success;
}


// This looks really ugly because it is.  The result of IsKerberosLogon()
// does not prove whether or not there are Kerberos tickets available to 
// be imported.  Only the call to khm_krb5_ms2mit() which actually attempts
// to import tickets can do that.  However, calling khm_krb5_ms2mit() can
// result in a TGS_REQ being sent to the KDC and since Leash_importable()
// is called quite often we want to avoid this if at all possible.
// Unfortunately, we have be shown at least one case in which the primary
// authentication package was not Kerberos and yet there were Kerberos 
// tickets available.  Therefore, if IsKerberosLogon() is not TRUE we 
// must call khm_krb5_ms2mit() but we still do not want to call it in a 
// tight loop so we cache the response and assume it won't change.
long FAR
Leash_importable(void)
{
    if ( IsKerberosLogon() )
        return TRUE;
    else {
        static int response = -1;
        if (response == -1) {
            response = khm_krb5_ms2mit(0);
        }
        return response;
    }
}

long FAR
Leash_import(void)
{
    if ( khm_krb5_ms2mit(1) ) {
        int lifetime;
        lifetime = Leash_get_default_lifetime() / 5;
		if (hKrb4 && Leash_get_default_use_krb4())
			Leash_convert524(0);
#ifndef NO_AFS
        {
            char c;
            char *r;
            char *t;
            char  cell[256];
            char  realm[256];
            int   i = 0;
            int   rcA = 0;

            krb5_context ctx = 0;
            krb5_error_code code = 0;
            krb5_ccache cc = 0;
            krb5_principal me = 0;

            if ( !pkrb5_init_context )
                goto cleanup;

            code = pkrb5_init_context(&ctx);
            if (code) goto cleanup;

            code = pkrb5_cc_default(ctx, &cc);
            if (code) goto cleanup;

            if (code = pkrb5_cc_get_principal(ctx, cc, &me))
                goto cleanup;

            for ( r=realm, t=cell, i=0; i<krb5_princ_realm(ctx, me)->length; r++,t++,i++ ) {
                c = krb5_princ_realm(ctx, me)->data[i];
                *r = c;
                *t = isupper(c) ? tolower(c) : c;
            }
            *r = *t = '\0';

            rcA = Leash_afs_klog("afs", cell, realm, lifetime);
            if (rcA)
                rcA = Leash_afs_klog("afs", "", realm, lifetime);

          cleanup:
            if (me) 
                pkrb5_free_principal(ctx, me);
            if (cc)
                pkrb5_cc_close(ctx, cc);
            if (ctx) 
                pkrb5_free_context(ctx);
        }
#endif /* NO_AFS */
        return 1;
    }
    return 0;
}

long
Leash_kdestroy(void)
{
    int k_errno;

    Leash_afs_unlog();
    khm_krb5_destroy_identity(NULL);

    if (pdest_tkt != NULL)
    {
        k_errno = (*pdest_tkt)();
        if (k_errno && (k_errno != RET_TKFIL))
            return KRBERR(k_errno);
    }

    return 0;
}

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
        strcpy(loc_addr,inet_ntoa(LocAddr));
	if ( strcmp(cred.address,loc_addr) != 0) {
            Leash_kdestroy ();
            break;
	}
        break;
    } // while()
    return 0;
} 

long FAR
not_an_API_LeashFreeTicketList(TicketList** ticketList) 
{
    TicketList* tempList = *ticketList, *killList; 

    //if (tempList == NULL)
    //return -1;

    while (tempList)
    {
        killList = tempList;
           
        tempList = (TicketList*)tempList->next;
        free(killList->theTicket);
        if (killList->tktEncType)
            free(killList->tktEncType);
        if (killList->keyEncType)
            free(killList->keyEncType);
        if (killList->addrCount) {
            int n;
            for ( n=0; n<killList->addrCount; n++) {
                if (killList->addrList[n])
                    free(killList->addrList[n]);
            }
        }
        if (killList->addrList)
            free(killList->addrList);
        if (killList->name)
            free(killList->name);
        if (killList->inst)
            free(killList->inst);
        if (killList->realm)
            free(killList->realm);
        free(killList);
    }

    *ticketList = NULL;
    return 0;
}


long FAR Leash_klist(HWND hlist, TICKETINFO FAR *ticketinfo)
{
    // Don't think this function will be used anymore - ADL 5-15-99    
    // Old fucntion to put tickets in a listbox control  
    // Use function  "not_an_API_LeashKRB4GetTickets()" instead! 
    char    pname[ANAME_SZ];
    char    pinst[INST_SZ];
    char    prealm[REALM_SZ];
    char    buf[MAX_K_NAME_SZ+40];
    LPSTR   cp;
    long    expdate;
    int     k_errno;
    CREDENTIALS c;
    int newtickets = 0;
    int open = 0;

    /*
     * Since krb_get_tf_realm will return a ticket_file error,
     * we will call tf_init and tf_close first to filter out
     * things like no ticket file.  Otherwise, the error that
     * the user would see would be 
     * klist: can't find realm of ticket file: No ticket file (tf_util)
     * instead of
     * klist: No ticket file (tf_util)
     */
    if (ptf_init == NULL)
        return(KSUCCESS);

    if (hlist) 
    { 
        SendMessage(hlist, WM_SETREDRAW, FALSE, 0L);
        SendMessage(hlist, LB_RESETCONTENT, 0, 0L);
    }                              
    com_addr();                    
    newtickets = NO_TICKETS;

    err_context = (LPSTR)"tktf1";

    /* Open ticket file */
    if (k_errno = (*ptf_init)((*ptkt_string)(), R_TKT_FIL))
    {
        goto cleanup;
    }
    /* Close ticket file */
    (void) (*ptf_close)();
    /*
     * We must find the realm of the ticket file here before calling
     * tf_init because since the realm of the ticket file is not
     * really stored in the principal section of the file, the
     * routine we use must itself call tf_init and tf_close.
     */
    err_context = "tf realm";
    if ((k_errno = (*pkrb_get_tf_realm)((*ptkt_string)(), prealm)) != KSUCCESS)
    {
        goto cleanup;
    }
    /* Open ticket file */
    err_context = "tf init";
    if (k_errno = (*ptf_init)((*ptkt_string)(), R_TKT_FIL)) 
    {
        goto cleanup;                            
    }

    open = 1;
    err_context = "tf pname";
    /* Get principal name and instance */
    if ((k_errno = (*ptf_get_pname)(pname)) || (k_errno = (*ptf_get_pinst)(pinst))) 
    {
        goto cleanup;             
    }

    /*
     * You may think that this is the obvious place to get the
     * realm of the ticket file, but it can't be done here as the
     * routine to do this must open the ticket file.  This is why
     * it was done before tf_init.
     */

    wsprintf((LPSTR)ticketinfo->principal,"%s%s%s%s%s", (LPSTR)pname,
             (LPSTR)(pinst[0] ? "." : ""), (LPSTR)pinst,
             (LPSTR)(prealm[0] ? "@" : ""), (LPSTR)prealm);
    newtickets = GOOD_TICKETS;

    err_context = "tf cred";
    while ((k_errno = (*ptf_get_cred)(&c)) == KSUCCESS) 
    {
        expdate = c.issue_date + c.lifetime * 5L * 60L;

        if (!lstrcmp((LPSTR)c.service, (LPSTR)TICKET_GRANTING_TICKET) && !lstrcmp((LPSTR)c.instance, (LPSTR)prealm)) 
        {
            ticketinfo->issue_date = c.issue_date;
            ticketinfo->lifetime = c.lifetime * 5L * 60L;
            ticketinfo->renew_till = 0;
        }

        cp = (LPSTR)buf;
        lstrcpy(cp, (LPSTR)short_date(&c.issue_date));
        cp += lstrlen(cp);
        wsprintf(cp,"\t%s\t%s%s%s%s%s",
                 (LPSTR)short_date(&expdate), (LPSTR)c.service,
                 (LPSTR)(c.instance[0] ? "." : ""),
                 (LPSTR)c.instance, (LPSTR)(c.realm[0] ? "@" : ""),
                 (LPSTR) c.realm);
        if (hlist)
            SendMessage(hlist, LB_ADDSTRING, 0, (LONG)(LPSTR)buf);
    } /* WHILE */

cleanup:

    if (open)
        (*ptf_close)(); /* close ticket file */

    if (hlist) 
    {
        SendMessage(hlist, WM_SETREDRAW, TRUE, 0L);
        InvalidateRect(hlist, NULL, TRUE);
        UpdateWindow(hlist);
    }
    if (k_errno == EOF)
        k_errno = 0;

    /* XXX the if statement directly below was inserted to eliminate
       an error 20 on Leash startup. The error occurs from an error
       number thrown from krb_get_tf_realm.  We believe this change
       does not eliminate other errors, but it may. */

    if (k_errno == RET_NOTKT)
        k_errno = 0;

    ticketinfo->btickets = newtickets;
    if (k_errno != 0)
        return KRBERR(k_errno);
    return 0;
}



static BOOL CALLBACK 
EnumChildProc(HWND hwnd, LPARAM lParam)
{
    HWND * h = (HWND *)lParam;
    *h = hwnd;
    return FALSE;
}


static HWND
FindFirstChildWindow(HWND parent)
{
    HWND hFirstChild = 0;
    EnumChildWindows(parent, EnumChildProc, (LPARAM) &hFirstChild);
	return hFirstChild;
}

void FAR
not_an_API_Leash_AcquireInitialTicketsIfNeeded(krb5_context context, krb5_principal desiredKrb5Principal) 
{
    krb5_error_code 	err;
    LSH_DLGINFO_EX      dlginfo;
    HGLOBAL hData;
    HWND    hLeash;
    HWND    hForeground;
    char		        *desiredName = 0;
    char                *desiredRealm = 0;
    char                *p;
    TicketList * list = NULL;
    TICKETINFO   ticketinfo;
    krb5_context        ctx;
    char newenv[256];
    char * env = 0;
    DWORD dwMsLsaImport = Leash_get_default_mslsa_import();

    char loginenv[16];
    BOOL prompt;

    GetEnvironmentVariable("KERBEROSLOGIN_NEVER_PROMPT", loginenv, sizeof(loginenv));
    prompt = (GetLastError() == ERROR_ENVVAR_NOT_FOUND);

    if ( !prompt || !pkrb5_init_context )
        return;

    ctx = context;
    env = getenv("KRB5CCNAME");
    if ( !env && context ) {
        sprintf(newenv,"KRB5CCNAME=%s",pkrb5_cc_default_name(ctx));
        env = (char *)putenv(newenv);
    }

    not_an_API_LeashKRB5GetTickets(&ticketinfo,&list,&ctx);
    not_an_API_LeashFreeTicketList(&list);

    if ( ticketinfo.btickets != GOOD_TICKETS && 
         Leash_get_default_mslsa_import() && Leash_importable() ) {
        // We have the option of importing tickets from the MSLSA
        // but should we?  Do the tickets in the MSLSA cache belong 
        // to the default realm used by Leash?  If so, import.  
        int import = 0;

        if ( dwMsLsaImport == 1 ) {             /* always import */
            import = 1;
        } else if ( dwMsLsaImport == 2 ) {      /* import when realms match */
            krb5_error_code code;
            krb5_ccache mslsa_ccache=0;
            krb5_principal princ = 0;
            char ms_realm[128] = "", *def_realm = 0, *r;
            int i;

            if (code = pkrb5_cc_resolve(ctx, "MSLSA:", &mslsa_ccache))
                goto cleanup;

            if (code = pkrb5_cc_get_principal(ctx, mslsa_ccache, &princ))
                goto cleanup;

            for ( r=ms_realm, i=0; i<krb5_princ_realm(ctx, princ)->length; r++, i++ ) {
                *r = krb5_princ_realm(ctx, princ)->data[i];
            }
            *r = '\0';

            if (code = pkrb5_get_default_realm(ctx, &def_realm))
                goto cleanup;

            import = !strcmp(def_realm, ms_realm);

          cleanup:
            if (def_realm)
                pkrb5_free_default_realm(ctx, def_realm);

            if (princ)
                pkrb5_free_principal(ctx, princ);

            if (mslsa_ccache)
                pkrb5_cc_close(ctx, mslsa_ccache);
        }

        if ( import ) {
            Leash_import();

            not_an_API_LeashKRB5GetTickets(&ticketinfo,&list,&ctx);
            not_an_API_LeashFreeTicketList(&list);
        }
    }

    if ( ticketinfo.btickets != GOOD_TICKETS ) 
    {
        /* do we want a specific client principal? */
        if (desiredKrb5Principal != NULL) {
            err = pkrb5_unparse_name (ctx, desiredKrb5Principal, &desiredName);
            if (!err) {
                dlginfo.username = desiredName;
                for (p = desiredName; *p && *p != '@'; p++);
                if ( *p == '@' ) {
                    *p = '\0';
                    desiredRealm = dlginfo.realm = ++p;
                }
            }
        }
		
#ifdef COMMENT
        memset(&dlginfo, 0, sizeof(LSH_DLGINFO_EX));
        dlginfo.size = sizeof(LSH_DLGINFO_EX);
        dlginfo.dlgtype = DLGTYPE_PASSWD;
        dlginfo.title = "Obtain Kerberos Ticket Getting Tickets";
        dlginfo.use_defaults = 1;

        err = Leash_kinit_dlg_ex(NULL, &dlginfo);
#else
        /* construct a marshalling of data
         *   <title><principal><realm>
         * then send to Leash
         */

        hData = GlobalAlloc( GHND, 4096 );
        hForeground = GetForegroundWindow();
        hLeash = FindWindow("LEASH.0WNDCLASS", NULL);
        SetForegroundWindow(hLeash);
        hLeash = FindFirstChildWindow(hLeash);
        if ( hData && hLeash ) {
            char * strs = GlobalLock( hData );
            if ( strs ) {
                strcpy(strs, "Obtain Kerberos Ticket Getting Tickets");
                strs += strlen(strs) + 1;
                if ( desiredName ) {
                    strcpy(strs, desiredName);
                    strs += strlen(strs) + 1;
					if (desiredRealm) {
						strcpy(strs, desiredRealm);
						strs += strlen(strs) + 1;
					}
                } else {
                    *strs = 0;
                    strs++;
                    *strs = 0;
                    strs++;
                }

                GlobalUnlock( hData );
                SendMessage(hLeash, 32809, 0, (LPARAM) hData);
            }

            GlobalFree( hData );
        }
        SetForegroundWindow(hForeground);
#endif
        if (desiredName != NULL)
            pkrb5_free_unparsed_name(ctx, desiredName);
    }

    if ( !env && context )
        putenv("KRB5CCNAME=");

    if ( !context )
        pkrb5_free_context(ctx);
}

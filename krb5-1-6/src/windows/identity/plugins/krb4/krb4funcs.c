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

#include <string.h>
#include <time.h>
#include <assert.h>
#include <strsafe.h>



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
        if ( strcmp(cred.address,loc_addr) != 0) {
            /* TODO: do something about this */
            //Leash_kdestroy ();
            break;
        }
        break;
    } // while()
    return 0;
} 


long 
khm_krb4_list_tickets(void) 
{
    char    ptktname[MAX_PATH + 5];
    char    pname[ANAME_SZ];
    char    pinst[INST_SZ];
    char    prealm[REALM_SZ];
    wchar_t wbuf[256];
    int     k_errno = 0;
    CREDENTIALS c;
    int newtickets = 0;
    int open = 0;
    khm_handle ident = NULL;
    khm_handle cred = NULL;
    time_t tt;
    FILETIME ft;

    kcdb_credset_flush(krb4_credset);

    // Since krb_get_tf_realm will return a ticket_file error,
    // we will call tf_init and tf_close first to filter out
    // things like no ticket file.  Otherwise, the error that
    // the user would see would be
    // klist: can't find realm of ticket file: No ticket file (tf_util)
    // instead of klist: No ticket file (tf_util)
    if (ptf_init == NULL)
        goto collect;

    com_addr();
    
    // Open ticket file
    if ((k_errno = (*ptf_init)((*ptkt_string)(), R_TKT_FIL)))
    {
        goto cleanup;
    }
    // Close ticket file 
    (void) (*ptf_close)();
    
    // We must find the realm of the ticket file here before calling
    // tf_init because since the realm of the ticket file is not
    // really stored in the principal section of the file, the
    // routine we use must itself call tf_init and tf_close.

    if ((k_errno = (*pkrb_get_tf_realm)((*ptkt_string)(), prealm)) != KSUCCESS)
    {
        goto cleanup;
    }
	
    // Open ticket file 
    if (k_errno = (*ptf_init)((*ptkt_string)(), R_TKT_FIL)) 
    {
        goto cleanup;
    }

    StringCchCopyA(ptktname, ARRAYLENGTH(ptktname), (*ptkt_string)());

    open = 1;

    // Get principal name and instance 
    if ((k_errno = (*ptf_get_pname)(pname)) || (k_errno = (*ptf_get_pinst)(pinst))) 
    {
        goto cleanup;
    }
	
    // You may think that this is the obvious place to get the
    // realm of the ticket file, but it can't be done here as the
    // routine to do this must open the ticket file.  This is why
    // it was done before tf_init.
    StringCbPrintf(wbuf, sizeof(wbuf), L"%S%S%S%S%S", (LPSTR)pname,
             (LPSTR)(pinst[0] ? "." : ""), (LPSTR)pinst,
             (LPSTR)(prealm[0] ? "@" : ""), (LPSTR)prealm);

    if(KHM_FAILED(kcdb_identity_create(wbuf, KCDB_IDENT_FLAG_CREATE, &ident)))
    {
        goto cleanup;
    }

    // Get KRB4 tickets
    while ((k_errno = (*ptf_get_cred)(&c)) == KSUCCESS)
    {
        StringCbPrintf(wbuf, sizeof(wbuf), L"%S%S%S%S%S",
            c.service,
            (c.instance[0] ? "." : ""),
            c.instance,
            (c.realm[0] ? "@" : ""),
            c.realm);

        if(KHM_FAILED(kcdb_cred_create(wbuf, ident, credtype_id_krb4, &cred)))
            continue;

        tt = c.issue_date + c.lifetime * 5L * 60L;
        TimetToFileTime(tt, &ft);
        kcdb_cred_set_attr(cred, KCDB_ATTR_EXPIRE, &ft, sizeof(ft));

        tt = c.issue_date;
        TimetToFileTime(tt, &ft);
        kcdb_cred_set_attr(cred, KCDB_ATTR_ISSUE, &ft, sizeof(ft));

        tt = c.lifetime * 5L * 60L;
        TimetToFileTimeInterval(tt, &ft);
        kcdb_cred_set_attr(cred, KCDB_ATTR_LIFETIME, &ft, sizeof(ft));

        AnsiStrToUnicode(wbuf, sizeof(wbuf), ptktname);
        kcdb_cred_set_attr(cred, KCDB_ATTR_LOCATION, wbuf, KCDB_CBSIZE_AUTO);

        kcdb_credset_add_cred(krb4_credset, cred, -1);

	kcdb_cred_release(cred);
    } // while

 cleanup:
    if (ptf_close == NULL)
        return(KSUCCESS);

    if (open)
        (*ptf_close)(); //close ticket file 

    if (k_errno == EOF)
        k_errno = 0;

    // XXX the if statement directly below was inserted to eliminate
    // an error NO_TKT_FIL on Leash startup. The error occurs from an
    // error number thrown from krb_get_tf_realm.  We believe this
    // change does not eliminate other errors, but it may.

    if (k_errno == NO_TKT_FIL)
        k_errno = 0;

    if(ident)
        kcdb_identity_release(ident);

#if 0
    /*TODO: Handle errors here */
    if (k_errno)
    {
        CHAR message[256];
        CHAR errBuf[256];
        LPCSTR errText; 

        if (!Lerror_message)
            return -1;

        errText = err_describe(errBuf, KRBERR(k_errno));

        sprintf(message, "%s\n\n%s failed", errText, functionName);
        MessageBox(NULL, message, "Kerberos Four", 
                   MB_OK | MB_ICONERROR | MB_TASKMODAL | MB_SETFOREGROUND);
    }
#endif

 collect:
    kcdb_credset_collect(NULL, krb4_credset, ident, credtype_id_krb4, NULL);

    return k_errno;
}

#define KRB_FILE                "KRB.CON"
#define KRBREALM_FILE           "KRBREALM.CON"
#define KRB5_FILE               "KRB5.INI"

BOOL 
khm_krb5_get_profile_file(LPSTR confname, UINT szConfname)
{
    char **configFile = NULL;
    if (pkrb5_get_default_config_files(&configFile)) 
    {
        GetWindowsDirectoryA(confname,szConfname);
        confname[szConfname-1] = '\0';

        StringCchCatA(confname, szConfname, "\\");
        StringCchCatA(confname, szConfname, KRB5_FILE);

        return FALSE;
    }
    
    *confname = 0;
    
    if (configFile)
    {
        StringCchCopyA(confname, szConfname, *configFile);
        pkrb5_free_config_files(configFile); 
    }
    
    if (!*confname)
    {
        GetWindowsDirectoryA(confname,szConfname);
        confname[szConfname-1] = '\0';

        StringCchCatA(confname, szConfname, "\\");
        StringCchCatA(confname, szConfname, KRB5_FILE);
    }
    
    return FALSE;
}

BOOL
khm_get_krb4_con_file(LPSTR confname, UINT szConfname)
{
    if (hKrb5 && !hKrb4) {
        // hold krb.con where krb5.ini is located
        CHAR krbConFile[MAX_PATH]="";
        LPSTR pFind;

        if (khm_krb5_get_profile_file(krbConFile, sizeof(krbConFile))) {
            GetWindowsDirectoryA(krbConFile,sizeof(krbConFile));
            krbConFile[MAX_PATH-1] = '\0';

            StringCbCatA(krbConFile, sizeof(krbConFile), "\\");
        }

        pFind = strrchr(krbConFile, '\\');

        if (pFind) {
            *pFind = '\0';

            StringCbCatA(krbConFile, sizeof(krbConFile), "\\");
            StringCbCatA(krbConFile, sizeof(krbConFile), KRB_FILE);
        } else {
            krbConFile[0] = '\0';
        }

        StringCchCopyA(confname, szConfname, krbConFile);
    } else if (hKrb4) { 
        size_t size = szConfname;
        memset(confname, '\0', szConfname);
        if (!pkrb_get_krbconf2(confname, &size)) {
            GetWindowsDirectoryA(confname,szConfname);
            confname[szConfname-1] = '\0';
            StringCchCatA(confname, szConfname, "\\");
            StringCchCatA(confname, szConfname, KRB_FILE);
        }
    }

    return FALSE;
}

int
readstring(FILE * file, char * buf, int len)
{
	int  c,i;
	memset(buf, '\0', sizeof(buf));
	for (i=0, c=fgetc(file); c != EOF ; c=fgetc(file), i++)
	{	
		if (i < sizeof(buf)) {
			if (c == '\n') {
                            buf[i] = '\0';
                            return i;
			} else {
                            buf[i] = (char)c;
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

    The string that is returned is a set of null terminated unicode strings, 
    each of which denotes one realm.  The set is terminated by a zero length
    null terminated string.

    The caller should free the returned string using free()

    \return The string with the list of realms or NULL if the operation fails.
*/
wchar_t * khm_krb5_get_realm_list(void) 
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
                retval = pprofile_get_subsection_names(profile,	rootsec, &sections);

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
#if _MSC_VER >= 1400
            !fopen_s(&file, krb_conf, "rt")
#else
            (file = fopen(krb_conf, "rt"))
#endif
            )
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

    A string will be returned that specifies the default realm.  The caller
    should free the string using free().

    Returns NULL if the operation fails.
*/
wchar_t * khm_krb5_get_default_realm(void)
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

static
char *
make_postfix(const char * base,
             const char * postfix,
             char ** rcopy)
{
    size_t base_size;
    size_t ret_size;
    char * copy = 0;
    char * ret = 0;
    size_t t;

    if (FAILED(StringCbLengthA(base, STRSAFE_MAX_CCH * sizeof(char), &t)))
        goto cleanup;

    base_size = t + 1;

    if (FAILED(StringCbLengthA(postfix, STRSAFE_MAX_CCH * sizeof(char), &t)))
        goto cleanup;

    ret_size = base_size + t + 1;

    copy = malloc(base_size);
    ret = malloc(ret_size);

    if (!copy || !ret)
        goto cleanup;

    StringCbCopyNA(copy, base_size, base, base_size);
    StringCbCopyNA(ret, ret_size, base, base_size);
    StringCbCopyNA(ret + (base_size - 1), ret_size - (base_size - 1),
                   postfix, ret_size - (base_size - 1));

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

void
khm_krb4_set_def_tkt_string(void) {
    wchar_t wtkt_string[MAX_PATH];
    char tkt_string[MAX_PATH];
    khm_size cb;

    cb = sizeof(wtkt_string);

    if (KHM_FAILED(khc_read_string(csp_params, L"TktString",
                                   wtkt_string, &cb)) ||
        wtkt_string[0] == L'\0') {

        pkrb_set_tkt_string(0);

    } else {

        UnicodeStrToAnsi(tkt_string, sizeof(tkt_string),
                         wtkt_string);
        pkrb_set_tkt_string(tkt_string);        
    }
}


static
long
make_temp_cache_v4(const char * postfix)
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

long
khm_krb4_changepwd(char * principal,
                   char * password,
                   char * newpassword,
                   char** error_str)
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

struct tgt_filter_data {
    khm_handle identity;
    wchar_t realm[KCDB_IDENT_MAXCCH_NAME];
};

khm_int32 KHMAPI
krb4_tgt_filter(khm_handle cred, khm_int32 flags, void * rock) {
    struct tgt_filter_data * pdata;
    wchar_t credname[KCDB_MAXCCH_NAME];
    wchar_t * t;
    khm_size cb;
    khm_int32 ctype;

    pdata = (struct tgt_filter_data *) rock;
    cb = sizeof(credname);

    if (KHM_FAILED(kcdb_cred_get_type(cred, &ctype)) ||
        ctype != credtype_id_krb4)
        return 0;

    if (KHM_FAILED(kcdb_cred_get_name(cred, credname, &cb)))
        return 0;

    if (wcsncmp(credname, L"krbtgt.", 7))
        return 0;

    t = wcsrchr(credname, L'@');
    if (t == NULL)
        return 0;

    if (wcscmp(t+1, pdata->realm))
        return 0;

    return 1;
}

khm_handle
khm_krb4_find_tgt(khm_handle credset, khm_handle identity) {
    khm_handle result = NULL;
    wchar_t idname[KCDB_IDENT_MAXCCH_NAME];
    wchar_t * t;
    khm_size cb;
    struct tgt_filter_data filter_data;

    cb = sizeof(idname);

    if (KHM_FAILED(kcdb_identity_get_name(identity,
                                          idname,
                                          &cb)))
        return NULL;
    
    t = wcsrchr(idname, L'@');
    if (t == NULL)
        return NULL;

    StringCbCopy(filter_data.realm, sizeof(filter_data.realm),
                 t + 1);
    filter_data.identity = identity;

    if (KHM_FAILED(kcdb_credset_find_filtered(credset,
                                              -1,
                                              krb4_tgt_filter,
                                              &filter_data,
                                              &result,
                                              NULL)))
        return NULL;
    else
        return result;
}

long
khm_convert524(khm_handle identity)
{
#ifdef NO_KRB5
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

    code = khm_krb5_initialize(identity, &ctx, &cc);
    if (code)
        goto cleanup;

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

    if (ctx)
        pkrb5_free_cred_contents(ctx, &increds);

    if (server) {
        pkrb5_free_principal(ctx, server);
    }

    if (me) {
        pkrb5_free_principal(ctx, me);
    }

    if (ctx && cc)
        pkrb5_cc_close(ctx, cc);

    if (ctx) {
        pkrb5_free_context(ctx);
    }

    return (code || icode);
#endif /* NO_KRB5 */    
}

long
khm_krb4_kinit(char * aname,
               char * inst,
               char * realm,
               long lifetime,
               char * password) {

    wchar_t * functionName = NULL;
    wchar_t * err_context = NULL;
    int rc4 = 0;
    int msg = 0;

    if (pkname_parse == NULL) {
        goto cleanup;
    }

    err_context = L"getting realm";
    if (!*realm && (rc4  = (int)(*pkrb_get_lrealm)(realm, 1))) {
        functionName = L"krb_get_lrealm()";
        msg = IDS_ERR_REALM;
        goto cleanup;
    }

    err_context = L"checking principal";
    if ((!*aname) || (!(rc4  = (int)(*pk_isname)(aname)))) {
        functionName = L"krb_get_lrealm()";
        msg = IDS_ERR_PRINCIPAL;
        goto cleanup;
    }

    /* optional instance */
    if (!(rc4 = (int)(*pk_isinst)(inst))) {
        functionName = L"k_isinst()";
        msg = IDS_ERR_INVINST;
        goto cleanup;
    }

    if (!(rc4 = (int)(*pk_isrealm)(realm))) {
        functionName = L"k_isrealm()";
        msg = IDS_ERR_REALM;
        goto cleanup;
    }

    khm_krb4_set_def_tkt_string();

    err_context = L"fetching ticket";	
    rc4 = (*pkrb_get_pw_in_tkt)(aname, inst, realm, "krbtgt", realm, 
                                lifetime, password);

    if (rc4) /* XXX: do we want: && (rc != NO_TKT_FIL) as well? */ { 
        functionName = L"krb_get_pw_in_tkt()";
        msg = IDS_ERR_PWINTKT;
        goto cleanup;
    }

    return 0;

 cleanup:
    {
        _report_sr0(KHERR_ERROR, msg);
        _location(functionName);
    }
    return rc4;
}


int khm_krb4_kdestroy(void) {
    int k_errno = 0;

    if (pdest_tkt != NULL)
    {
        k_errno = (*pdest_tkt)();
        if (k_errno && (k_errno != RET_TKFIL))
            return KRBERR(k_errno);
    }

    return k_errno;
}

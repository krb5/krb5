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

#include<windows.h>
#include<kcreddb.h>
#include<kherror.h>
#include<dynimport.h>

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

    LPCSTR          functionName;
    int             freeContextFlag;
    krb5_error_code	rc;
    krb5_flags          flags = 0;

    if (pkrb5_init_context == NULL)
        return 1;

    if (*ctx == 0 && (rc = (*pkrb5_init_context)(ctx)))
    {
        functionName = "krb5_init_context()";
        freeContextFlag = 0;
        goto on_error;
    }

    if(*cache == 0) {
        wchar_t wccname[256];
        khm_size cbwccname;

        if(ident != NULL) {
            cbwccname = sizeof(wccname);
            do {
                char ccname[256];

                if(KHM_FAILED(kcdb_identity_get_attrib(ident, L"Krb5CCName", NULL, wccname, &cbwccname)))
                    break;

                if(UnicodeStrToAnsi(ccname, sizeof(ccname), wccname) == 0)
                    break;

                if((*pkrb5_cc_resolve)(*ctx, ccname, cache)) {
                    functionName = "krb5_cc_resolve()";
                    freeContextFlag = 1;
                    goto on_error;
                }
            } while(FALSE);
        }

        if (*cache == 0 && (rc = (*pkrb5_cc_default)(*ctx, cache)))
        {
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
        else if ((rc == KRB5_FCC_NOFILE || rc == KRB5_CC_NOTFOUND) && *ctx != NULL)
        {
            if (*cache != NULL)
                (*pkrb5_cc_close)(*ctx, *cache);
        }
        return rc;
    }
    return 0;

on_error:
    return khm_krb5_error(rc, functionName, freeContextFlag, ctx, cache);
#endif //!NO_KRB5
}

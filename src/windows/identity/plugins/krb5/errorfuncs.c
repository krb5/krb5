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

#include<krbcred.h>
#include<kherror.h>

extern void (__cdecl *pinitialize_krb_error_func)();
extern void (__cdecl *pinitialize_kadm_error_table)();


khm_int32 init_error_funcs()
{
    return KHM_ERROR_SUCCESS;
}

khm_int32 exit_error_funcs()
{
    return KHM_ERROR_SUCCESS;
}

#ifdef DEPRECATED_REMOVABLE
HWND GetRootParent (HWND Child)
{
    HWND Last;
    while (Child)
    {
        Last = Child;
        Child = GetParent (Child);
    }
    return Last;
}
#endif

void khm_err_describe(long code, wchar_t * buf, khm_size cbbuf, 
                      DWORD * suggestion,
                      kherr_suggestion * suggest_code)
{
    const char * com_err_msg;
    int offset;
    long table_num;
    DWORD msg_id = 0;
    DWORD sugg_id = 0;
    kherr_suggestion sugg_code = KHERR_SUGGEST_NONE;

    if (suggestion == NULL || buf == NULL || cbbuf == 0 || suggest_code == 0)
        return;

    *buf = L'\0';

    offset = (int) (code & 255);
    table_num = code - offset;
    com_err_msg = perror_message(code);

    *suggestion = 0;
    *suggest_code = KHERR_SUGGEST_NONE;

    if (WSABASEERR <= code && code < (WSABASEERR + 1064)) {
        /* winsock error */
        table_num = WSABASEERR;
        offset = code - WSABASEERR;
    }

    switch(table_num)
    {
    case krb_err_base:
    case kadm_err_base:
    case WSABASEERR:
	break;
    default:

        if (code == KRB5KRB_AP_ERR_BAD_INTEGRITY) {
            *suggestion = MSG_ERR_S_INTEGRITY;
        }
        *suggest_code = KHERR_SUGGEST_RETRY;
        AnsiStrToUnicode(buf, cbbuf, com_err_msg);
	return;
    }

    if (table_num == krb_err_base) {
        switch(offset) {
        case KDC_NAME_EXP:           /* 001 Principal expired */
        case KDC_SERVICE_EXP:        /* 002 Service expired */
        case KDC_AUTH_EXP:           /* 003 Auth expired */
        case KDC_PKT_VER:            /* 004 Protocol version unknown */
        case KDC_P_MKEY_VER:         /* 005 Wrong master key version */
        case KDC_S_MKEY_VER:         /* 006 Wrong master key version */
        case KDC_BYTE_ORDER:         /* 007 Byte order unknown */
        case KDC_PR_N_UNIQUE:        /* 009 Principal not unique */
        case KDC_NULL_KEY:           /* 010 Principal has null key */
        case KDC_GEN_ERR:            /* 011 Generic error from KDC */
        case INTK_W_NOTALL   :       /* 061 Not ALL tickets returned */
        case INTK_PROT       :       /* 063 Protocol Error */
        case INTK_ERR        :       /* 070 Other error */
            msg_id = MSG_ERR_UNKNOWN;
            sugg_code = KHERR_SUGGEST_RETRY;
            break;

        case KDC_PR_UNKNOWN:         /* 008 Principal unknown */
            msg_id = MSG_ERR_PR_UNKNOWN;
            sugg_code = KHERR_SUGGEST_RETRY;
            break;
        case GC_TKFIL                : /* 021 Can't read ticket file */
        case GC_NOTKT                : /* 022 Can't find ticket or TGT */
            msg_id = MSG_ERR_TKFIL;
            sugg_id = MSG_ERR_S_TKFIL;
            sugg_code = KHERR_SUGGEST_RETRY;
            break;
        case MK_AP_TGTEXP    :  /* 026 TGT Expired */
            /* no extra error msg */
            break;

        case RD_AP_TIME              : /* 037 delta_t too big */
            msg_id = MSG_ERR_CLOCKSKEW;
            sugg_id = MSG_ERR_S_CLOCKSKEW;
            sugg_code = KHERR_SUGGEST_RETRY;
            break;

        case RD_AP_UNDEC             : /* 031 Can't decode
                                          authenticator */
        case RD_AP_EXP               : /* 032 Ticket expired */
        case RD_AP_NYV               : /* 033 Ticket not yet valid */
        case RD_AP_REPEAT    :  /* 034 Repeated request */
        case RD_AP_NOT_US    :  /* 035 The ticket isn't for us */
        case RD_AP_INCON             : /* 036 Request is inconsistent */
        case RD_AP_BADD              : /* 038 Incorrect net address */
        case RD_AP_VERSION   :  /* 039 protocol version mismatch */
        case RD_AP_MSG_TYPE  :  /* 040 invalid msg type */
        case RD_AP_MODIFIED  :  /* 041 message stream modified */
        case RD_AP_ORDER             : /* 042 message out of order */
        case RD_AP_UNAUTHOR  :  /* 043 unauthorized request */
            /* no extra error msg */
            sugg_code = KHERR_SUGGEST_RETRY;
            break;

        case GT_PW_NULL:     /* 51    Current PW is null */
        case GT_PW_BADPW:    /* 52    Incorrect current password */
        case GT_PW_PROT:     /* 53    Protocol Error */
        case GT_PW_KDCERR:   /* 54    Error returned by KDC */
        case GT_PW_NULLTKT:  /* 55    Null tkt returned by KDC */
            /* no error msg yet */
            sugg_code = KHERR_SUGGEST_RETRY;
            break;
	  
            /* Values returned by send_to_kdc */
        case SKDC_RETRY   :     /* 56    Retry count exceeded */
        case SKDC_CANT    :     /* 57    Can't send request */
            msg_id = MSG_ERR_KDC_CONTACT;
            break;
            /* no error message on purpose: */
        case INTK_BADPW      :  /* 062 Incorrect password */
            sugg_code = KHERR_SUGGEST_RETRY;
            break;
        default:
            /* no extra error msg */
            break;
        }
    } else if (table_num == kadm_err_base) {
        switch(code) {
        case KADM_INSECURE_PW:
            /* if( kadm_info != NULL ){
             * wsprintf(buf, "%s\n%s", com_err_msg, kadm_info);
             * } else {
             * wsprintf(buf, "%s\nPlease see the help file for information "
             * "about secure passwords.", com_err_msg);
             * }
             * com_err_msg = buf;
             */

            /* The above code would be preferred since it allows site
             * specific information to be delivered from the Kerberos
             * server. However the message box is too small for VGA
             * screens.  It does work well if we only have to support
             * 1024x768
             */

            msg_id = MSG_ERR_INSECURE_PW;
            sugg_code = KHERR_SUGGEST_RETRY;
            break;
	
        default:
            /* no extra error msg */
            break;
        }
    } else if (table_num == WSABASEERR) {
        switch(code) {
        case WSAENETDOWN:
            msg_id = MSG_ERR_NETDOWN;
            sugg_id = MSG_ERR_S_NETRETRY;
            sugg_code = KHERR_SUGGEST_RETRY;
            break;

        case WSATRY_AGAIN:
            msg_id = MSG_ERR_TEMPDOWN;
            sugg_id = MSG_ERR_S_TEMPDOWN;
            sugg_code = KHERR_SUGGEST_RETRY;
            break;

        case WSAENETUNREACH:
        case WSAENETRESET:
        case WSAECONNABORTED:
        case WSAECONNRESET:
        case WSAETIMEDOUT:
        case WSAECONNREFUSED:
        case WSAEHOSTDOWN:
        case WSAEHOSTUNREACH:
            msg_id = MSG_ERR_NOHOST;
            sugg_id = MSG_ERR_S_NOHOST;
            sugg_code = KHERR_SUGGEST_RETRY;
            break;
        }
    }

    if (msg_id != 0) {
        FormatMessage(FORMAT_MESSAGE_FROM_HMODULE |
                      FORMAT_MESSAGE_IGNORE_INSERTS,
                      KHERR_HMODULE,
                      msg_id,
                      0,
                      buf,
                      (int) (cbbuf / sizeof(buf[0])),
                      NULL);
    }

    if (sugg_id != 0) {
        *suggestion = sugg_id;
    }

    if (sugg_code != KHERR_SUGGEST_NONE)
        *suggest_code = sugg_code;
}

#ifdef DEPRECATED_REMOVABLE
int lsh_com_err_proc (LPSTR whoami, long code,
                              LPSTR fmt, va_list args)
{
    int retval;
    HWND hOldFocus;
    char buf[1024], *cp;
    WORD mbformat = MB_OK | MB_ICONEXCLAMATION;
  
    cp = buf;
    memset(buf, '\0', sizeof(buf));
    cp[0] = '\0';
  
    if (code)
    {
        err_describe(buf, code);
        while (*cp)
            cp++;
    }
  
    if (fmt)
    {
        if (fmt[0] == '%' && fmt[1] == 'b')
	{
            fmt += 2;
            mbformat = va_arg(args, WORD);
            /* if the first arg is a %b, we use it for the message
               box MB_??? flags. */
	}
        if (code)
	{
            *cp++ = '\n';
            *cp++ = '\n';
	}
        wvsprintfA((LPSTR)cp, fmt, args);
    }
    hOldFocus = GetFocus();
    retval = MessageBoxA(/*GetRootParent(hOldFocus)*/NULL, buf, whoami, 
                        mbformat | MB_ICONHAND | MB_TASKMODAL);
    SetFocus(hOldFocus);
    return retval;
}
#endif

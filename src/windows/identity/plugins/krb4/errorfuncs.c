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

#include<strsafe.h>

extern void (__cdecl *pinitialize_krb_error_func)();
extern void (__cdecl *pinitialize_kadm_error_table)();


khm_int32 init_error_funcs()
{

#if 0
    /*TODO: Do something about this */
    if (plsh_LoadKrb4LeashErrorTables)
            plsh_LoadKrb4LeashErrorTables(hLeashInst, 0);
#endif
    return KHM_ERROR_SUCCESS;
}

khm_int32 exit_error_funcs()
{
    return KHM_ERROR_SUCCESS;
}

// Global Variables.
static long lsh_errno;
static char *err_context;       /* error context */
extern int (*Lcom_err)(LPSTR,long,LPSTR,...);
extern LPSTR (*Lerror_message)(long);
extern LPSTR (*Lerror_table_name)(long);

#ifdef WIN16
#define UNDERSCORE "_"
#else
#define UNDERSCORE
#endif

HWND GetRootParent (HWND Child)
{
    HWND Last = NULL;
    while (Child)
    {
        Last = Child;
        Child = GetParent (Child);
    }
    return Last;
}


LPSTR err_describe(LPSTR buf, size_t len, long code)
{
    LPSTR cp, com_err_msg;
    int offset;
    long table_num;
    char *etype;

    offset = (int) (code & 255);
    table_num = code - offset;
    com_err_msg = Lerror_message(code);

    switch(table_num)
    {
    case krb_err_base:
    case kadm_err_base:
	break;
    default:
        StringCbCopyA(buf, len, com_err_msg);
	return buf;
    }

    cp = buf;
    if (table_num == krb_err_base)
        switch(offset)
        {
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
            com_err_msg = "Something weird happened... try again, and if Leash"
                " continues to fail, contact Network Services as listed in the "
                "About box.";
            break;
        case KDC_PR_UNKNOWN:         /* 008 Principal unknown */
            com_err_msg = "You have entered an unknown username/instance/realm"
                " combination.";
            break;
        case GC_TKFIL                :       /* 021 Can't read ticket file */
        case GC_NOTKT                :       /* 022 Can't find ticket or TGT */
            com_err_msg = "Something is wrong with the memory where your "
                "tickets are stored. Try exiting Windows and restarting your "
                "computer.";
            break;
        case MK_AP_TGTEXP    :       /* 026 TGT Expired */
            /* no extra error msg */
            break;
        case RD_AP_TIME              :       /* 037 delta_t too big */
            com_err_msg = "Your computer's clock is out of sync with the "
                "Kerberos server.  Please see the help file about correcting "
                "your clock.";
            break;

        case RD_AP_UNDEC             :       /* 031 Can't decode authenticator */
        case RD_AP_EXP               :       /* 032 Ticket expired */
        case RD_AP_NYV               :       /* 033 Ticket not yet valid */
        case RD_AP_REPEAT    :       /* 034 Repeated request */
        case RD_AP_NOT_US    :       /* 035 The ticket isn't for us */
        case RD_AP_INCON             :       /* 036 Request is inconsistent */
        case RD_AP_BADD              :       /* 038 Incorrect net address */
        case RD_AP_VERSION   :       /* 039 protocol version mismatch */
        case RD_AP_MSG_TYPE  :       /* 040 invalid msg type */
        case RD_AP_MODIFIED  :       /* 041 message stream modified */
        case RD_AP_ORDER             :       /* 042 message out of order */
        case RD_AP_UNAUTHOR  :       /* 043 unauthorized request */
            /* no extra error msg */
            break;
        case GT_PW_NULL:     /* 51    Current PW is null */
        case GT_PW_BADPW:    /* 52    Incorrect current password */
        case GT_PW_PROT:     /* 53    Protocol Error */
        case GT_PW_KDCERR:   /* 54    Error returned by KDC */
        case GT_PW_NULLTKT:  /* 55    Null tkt returned by KDC */
            /* no error msg yet */
            break;

            /* Values returned by send_to_kdc */
        case SKDC_RETRY   :  /* 56    Retry count exceeded */
        case SKDC_CANT    :  /* 57    Can't send request */
            com_err_msg = "Cannot contact the kerberos server for the selected realm.";
            break;
            /* no error message on purpose: */
        case INTK_BADPW      :       /* 062 Incorrect password */
            break;
        default:
            /* no extra error msg */
            break;
        }
    else
        switch(code)
        {
        case KADM_INSECURE_PW:
            /* if( kadm_info != NULL ){
             * wsprintf(buf, "%s\n%s", com_err_msg, kadm_info);
             * } else {
             * wsprintf(buf, "%s\nPlease see the help file for information "
             * "about secure passwords.", com_err_msg);
             * }
             * com_err_msg = buf;
             */

            /* The above code would be preferred since it allows site specific
             * information to be delivered from the Kerberos server. However the
             * message box is too small for VGA screens.
             * It does work well if we only have to support 1024x768
             */

            com_err_msg = "You have entered an insecure or weak password.";

        default:
            /* no extra error msg */
            break;
        }
    if(com_err_msg != buf) {
        StringCbCopyA(buf, len, com_err_msg);
    }
    cp = buf + strlen(buf);
    *cp++ = '\n';
    switch(table_num) {
    case krb_err_base:
        etype = "Kerberos";
        break;
    case kadm_err_base:
        etype = "Kerberos supplemental";
        break;
    default:
        etype = Lerror_table_name(table_num);
        break;
    }
    StringCbPrintfA((LPSTR) cp, len - (cp-buf), (LPSTR) "(%s error %d"
#ifdef DEBUG_COM_ERR
             " (absolute error %ld)"
#endif
             ")", etype, offset
             //")\nPress F1 for help on this error.", etype, offset
#ifdef DEBUG_COM_ERR
             , code
#endif
        );

    return (LPSTR)buf;
}

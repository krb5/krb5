/*
 * ms2mit.c
 *
 */
/***********************************************************
        Copyright 2000 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of Carnegie Mellon
University not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE FOR
ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
******************************************************************/


#define UNICODE
#define _UNICODE

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <time.h>
#define SECURITY_WIN32
#include <security.h>
#include <ntsecapi.h>

#include <krb5.h>
#include <com_err.h>
#include <assert.h>

VOID
ShowWinError(
    LPSTR szAPI,
    DWORD dwError
    )
{
#define MAX_MSG_SIZE 256

    // TODO - Write errors to event log so that scripts that don't
    // check for errors will still get something in the event log

    WCHAR szMsgBuf[MAX_MSG_SIZE];
    DWORD dwRes;

    printf("Error calling function %s: %lu\n", szAPI, dwError);

    dwRes = FormatMessage (
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        dwError,
        MAKELANGID (LANG_ENGLISH, SUBLANG_ENGLISH_US),
        szMsgBuf,
        MAX_MSG_SIZE,
        NULL);
    if (0 == dwRes) {
        printf("FormatMessage failed with %d\n", GetLastError());
        ExitProcess(EXIT_FAILURE);
    }

    printf("%S",szMsgBuf);
}

VOID
ShowLsaError(
    LPSTR szAPI,
    NTSTATUS Status
    )
{
    //
    // Convert the NTSTATUS to Winerror. Then call ShowWinError().
    //
    ShowWinError(szAPI, LsaNtStatusToWinError(Status));
}



BOOL
WINAPI
UnicodeToANSI(
    LPTSTR lpInputString,
    LPSTR lpszOutputString,
    int nOutStringLen
    )
{
#ifndef WIN32S
    CPINFO CodePageInfo;

    GetCPInfo(CP_ACP, &CodePageInfo);

    if (CodePageInfo.MaxCharSize > 1)
        // Only supporting non-Unicode strings
        return FALSE;
    else if (((LPBYTE) lpInputString)[1] == '\0')
    {
        // Looks like unicode, better translate it
        WideCharToMultiByte(CP_ACP, 0, (LPCWSTR) lpInputString, -1,
                            lpszOutputString, nOutStringLen, NULL, NULL);
    }
    else
        lstrcpyA(lpszOutputString, (LPSTR) lpInputString);
#else
    lstrcpy(lpszOutputString, (LPSTR) lpInputString);
#endif
    return TRUE;
}  // UnicodeToANSI

VOID
WINAPI
ANSIToUnicode(
    LPSTR  lpInputString,
    LPTSTR lpszOutputString,
    int nOutStringLen
    )
{

#ifndef WIN32S
    CPINFO CodePageInfo;

    lstrcpy(lpszOutputString, (LPTSTR) lpInputString);

    GetCPInfo(CP_ACP, &CodePageInfo);

    if (CodePageInfo.MaxCharSize > 1)
        // It must already be a Unicode string
        return;
    else if (((LPBYTE) lpInputString)[1] != '\0')
    {
        // Looks like ANSI, better translate it
        MultiByteToWideChar(CP_ACP, 0, (LPCSTR) lpInputString, -1,
                            (LPWSTR) lpszOutputString, nOutStringLen);
    }
    else
        lstrcpy(lpszOutputString, (LPTSTR) lpInputString);
#endif
}  // ANSIToUnicode


void
MSPrincToMITPrinc(
    KERB_EXTERNAL_NAME *msprinc,
    WCHAR *realm,
    krb5_context context,
    krb5_principal *principal
    )
{
    WCHAR princbuf[512],tmpbuf[128];
    char aname[512];
    USHORT i;
    princbuf[0]=0;
    for (i=0;i<msprinc->NameCount;i++) {
        wcsncpy(tmpbuf, msprinc->Names[i].Buffer,
                msprinc->Names[i].Length/sizeof(WCHAR));
        tmpbuf[msprinc->Names[i].Length/sizeof(WCHAR)]=0;
        if (princbuf[0])
            wcscat(princbuf, L"/");
        wcscat(princbuf, tmpbuf);
    }
    wcscat(princbuf, L"@");
    wcscat(princbuf, realm);
    UnicodeToANSI(princbuf, aname, sizeof(aname));
    krb5_parse_name(context, aname, principal);
}


time_t
FileTimeToUnixTime(
    LARGE_INTEGER *ltime
    )
{
    FILETIME filetime, localfiletime;
    SYSTEMTIME systime;
    struct tm utime;
    filetime.dwLowDateTime=ltime->LowPart;
    filetime.dwHighDateTime=ltime->HighPart;
    FileTimeToLocalFileTime(&filetime, &localfiletime);
    FileTimeToSystemTime(&localfiletime, &systime);
    utime.tm_sec=systime.wSecond;
    utime.tm_min=systime.wMinute;
    utime.tm_hour=systime.wHour;
    utime.tm_mday=systime.wDay;
    utime.tm_mon=systime.wMonth-1;
    utime.tm_year=systime.wYear-1900;
    utime.tm_isdst=-1;
    return(mktime(&utime));
}

void
MSSessionKeyToMITKeyblock(
    KERB_CRYPTO_KEY *mskey,
    krb5_context context,
    krb5_keyblock *keyblock
    )
{
    krb5_keyblock tmpblock;
    tmpblock.magic=KV5M_KEYBLOCK;
    tmpblock.enctype=mskey->KeyType;
    tmpblock.length=mskey->Length;
    tmpblock.contents=mskey->Value;
    krb5_copy_keyblock_contents(context, &tmpblock, keyblock);
}


void
MSFlagsToMITFlags(
    ULONG msflags,
    ULONG *mitflags
    )
{
    *mitflags=msflags;
}

void
MSTicketToMITTicket(
    KERB_EXTERNAL_TICKET *msticket,
    krb5_context context,
    krb5_data *ticket
    )
{
    krb5_data tmpdata, *newdata;
    tmpdata.magic=KV5M_DATA;
    tmpdata.length=msticket->EncodedTicketSize;
    tmpdata.data=msticket->EncodedTicket;
    // todo: fix this up a little. this is ugly and will break krb_free_data()
    krb5_copy_data(context, &tmpdata, &newdata);
    memcpy(ticket, newdata, sizeof(krb5_data));
}

void
MSCredToMITCred(
    KERB_EXTERNAL_TICKET *msticket,
    krb5_context context,
    krb5_creds *creds
    )
{
    WCHAR wtmp[128];
    ZeroMemory(creds, sizeof(krb5_creds));
    creds->magic=KV5M_CREDS;
    wcsncpy(wtmp, msticket->TargetDomainName.Buffer,
            msticket->TargetDomainName.Length/sizeof(WCHAR));
    wtmp[msticket->TargetDomainName.Length/sizeof(WCHAR)]=0;
    MSPrincToMITPrinc(msticket->ClientName, wtmp, context, &creds->client);
    wcsncpy(wtmp, msticket->DomainName.Buffer,
            msticket->DomainName.Length/sizeof(WCHAR));
    wtmp[msticket->DomainName.Length/sizeof(WCHAR)]=0;
    MSPrincToMITPrinc(msticket->ServiceName, wtmp, context, &creds->server);
    MSSessionKeyToMITKeyblock(&msticket->SessionKey, context, 
                              &creds->keyblock);
    MSFlagsToMITFlags(msticket->TicketFlags, &creds->ticket_flags);
    creds->times.starttime=FileTimeToUnixTime(&msticket->StartTime);
    creds->times.endtime=FileTimeToUnixTime(&msticket->EndTime);
    creds->times.renew_till=FileTimeToUnixTime(&msticket->RenewUntil);

    // krb5_cc_store_cred crashes downstream if creds->addresses is NULL.
    // unfortunately, the MS interface doesn't seem to return a list of
    // addresses as part of the credentials information. for now i'll just
    // use krb5_os_localaddr to mock up the address list. is this sufficient?
    krb5_os_localaddr(context, &creds->addresses);

    MSTicketToMITTicket(msticket, context, &creds->ticket);
}

BOOL
PackageConnectLookup(
    HANDLE *pLogonHandle,
    ULONG *pPackageId
    )
{
    LSA_STRING Name;
    NTSTATUS Status;

    Status = LsaConnectUntrusted(
        pLogonHandle
        );

    if (FAILED(Status))
    {
        ShowLsaError("LsaConnectUntrusted", Status);
        return FALSE;
    }

    Name.Buffer = MICROSOFT_KERBEROS_NAME_A;
    Name.Length = strlen(Name.Buffer);
    Name.MaximumLength = Name.Length + 1;

    Status = LsaLookupAuthenticationPackage(
        *pLogonHandle,
        &Name,
        pPackageId
        );

    if (FAILED(Status))
    {
        ShowLsaError("LsaLookupAuthenticationPackage", Status);
        return FALSE;
    }

    return TRUE;

}


DWORD
ConcatenateUnicodeStrings(
    UNICODE_STRING *pTarget,
    UNICODE_STRING Source1,
    UNICODE_STRING Source2
    )
{
    //
    // The buffers for Source1 and Source2 cannot overlap pTarget's
    // buffer.  Source1.Length + Source2.Length must be <= 0xFFFF,
    // otherwise we overflow...
    //

    USHORT TotalSize = Source1.Length + Source2.Length;
    PBYTE buffer = (PBYTE) pTarget->Buffer;

    if (TotalSize > pTarget->MaximumLength)
        return ERROR_INSUFFICIENT_BUFFER;

    pTarget->Length = TotalSize;
    memcpy(buffer, Source1.Buffer, Source1.Length);
    memcpy(buffer + Source1.Length, Source2.Buffer, Source2.Length);
    return ERROR_SUCCESS;
}

BOOL
GetMSTGT(
    HANDLE LogonHandle,
    ULONG PackageId,
    KERB_EXTERNAL_TICKET **ticket
    )
{
    //
    // INVARIANTS:
    //
    //   (FAILED(Status) || FAILED(SubStatus)) ==> error
    //   bIsLsaError ==> LsaCallAuthenticationPackage() error
    //

    //
    // NOTE:
    //
    // The updated code leaks memory, but so does the old code.  The
    // whole program is full of leaks.  Since it's short-lived
    // process, it is ok.
    //

    BOOL bIsLsaError = FALSE;
    NTSTATUS Status = 0;
    NTSTATUS SubStatus = 0;

    UNICODE_STRING TargetPrefix;

    KERB_QUERY_TKT_CACHE_REQUEST CacheRequest;
    PKERB_RETRIEVE_TKT_REQUEST pTicketRequest;
    PKERB_RETRIEVE_TKT_RESPONSE pTicketResponse = NULL;
    ULONG RequestSize;
    ULONG ResponseSize;
    USHORT TargetSize;

    CacheRequest.MessageType = KerbRetrieveTicketMessage;
    CacheRequest.LogonId.LowPart = 0;
    CacheRequest.LogonId.HighPart = 0;

    pTicketResponse = NULL;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        &CacheRequest,
        sizeof(CacheRequest),
        &pTicketResponse,
        &ResponseSize,
        &SubStatus
        );

    if (FAILED(Status) || FAILED(SubStatus))
    {
        bIsLsaError = TRUE;
        goto cleanup;
    }

    if (pTicketResponse->Ticket.SessionKey.KeyType == KERB_ETYPE_DES_CBC_CRC)
    {
        // all done!
        goto cleanup;
    }

    //
    // Set up the "krbtgt/" target prefix into a UNICODE_STRING so we
    // can easily concatenate it later.
    //

    TargetPrefix.Buffer = L"krbtgt/";
    TargetPrefix.Length = wcslen(TargetPrefix.Buffer) * sizeof(WCHAR);
    TargetPrefix.MaximumLength = TargetPrefix.Length;

    //
    // We will need to concatenate the "krbtgt/" prefix and the previous
    // response's target domain into our request's target name.
    //
    // Therefore, first compute the necessary buffer size for that.
    //
    // Note that we might theoretically have integer overflow.
    //

    TargetSize = TargetPrefix.Length +
        pTicketResponse->Ticket.TargetDomainName.Length;

    //
    // The ticket request buffer needs to be a single buffer.  That buffer
    // needs to include the buffer for the target name.
    //

    RequestSize = sizeof(*pTicketRequest) + TargetSize;

    //
    // Allocate the request buffer and make sure it's zero-filled.
    //

    pTicketRequest = (PKERB_RETRIEVE_TKT_REQUEST)
        LocalAlloc(LMEM_ZEROINIT, RequestSize);
    if (!pTicketRequest)
    {
        Status = GetLastError();
        goto cleanup;
    }

    //
    // Concatenate the target prefix with the previous reponse's
    // target domain.
    //

    pTicketRequest->TargetName.Length = 0;
    pTicketRequest->TargetName.MaximumLength = TargetSize;
    pTicketRequest->TargetName.Buffer = (PWSTR) (pTicketRequest + 1);
    Status = ConcatenateUnicodeStrings(&(pTicketRequest->TargetName),
                                       TargetPrefix,
                                       pTicketResponse->Ticket.TargetDomainName);
    assert(SUCCEEDED(Status));

    //
    // Intialize the requst of the request.
    //

    pTicketRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    pTicketRequest->LogonId.LowPart = 0;
    pTicketRequest->LogonId.HighPart = 0;
    // Note: pTicketRequest->TargetName set up above
    pTicketRequest->CacheOptions = KERB_RETRIEVE_TICKET_DONT_USE_CACHE;
    pTicketRequest->TicketFlags = 0L;
    pTicketRequest->EncryptionType = ENCTYPE_DES_CBC_CRC;

    //
    // Free the previous response buffer so we can get the new response.
    //

    LsaFreeReturnBuffer(pTicketResponse);
    pTicketResponse = NULL;

    Status = LsaCallAuthenticationPackage(
        LogonHandle,
        PackageId,
        pTicketRequest,
        RequestSize,
        &pTicketResponse,
        &ResponseSize,
        &SubStatus
        );

    if (FAILED(Status) || FAILED(SubStatus))
    {
        bIsLsaError = TRUE;
        goto cleanup;
    }

 cleanup:
    if (FAILED(Status) || FAILED(SubStatus))
    {
        if (bIsLsaError)
        {
            // XXX - Will be fixed later
            if (FAILED(Status))
                ShowLsaError("LsaCallAuthenticationPackage", Status);
            if (FAILED(SubStatus))
                ShowLsaError("LsaCallAuthenticationPackage", SubStatus);
        }
        else
        {
            ShowWinError("GetMSTGT", Status);
        }

        if (pTicketResponse)
            LsaFreeReturnBuffer(pTicketResponse);

        return(FALSE);
    }

    *ticket = &(pTicketResponse->Ticket);
    return(TRUE);
}

void
main(
    int argc,
    char *argv[]
    )
{
    krb5_context kcontext;
    krb5_error_code code;
    krb5_creds creds;
    krb5_ccache ccache=NULL;
    krb5_get_init_creds_opt opts;
    char *cache_name=NULL;
    HANDLE LogonHandle=NULL;
    ULONG PackageId;

    KERB_EXTERNAL_TICKET *msticket;
    if(!PackageConnectLookup(&LogonHandle, &PackageId))
        exit(1);

    if (GetMSTGT(LogonHandle, PackageId, &msticket)==FALSE)
        exit(1);
    if (code = krb5_init_context(&kcontext)) {
        com_err(argv[0], code, "while initializing kerberos library");
        exit(1);
    }
    krb5_get_init_creds_opt_init(&opts);
    MSCredToMITCred(msticket, kcontext, &creds);
    if (code = krb5_cc_default(kcontext, &ccache)) {
        com_err(argv[0], code, "while getting default ccache");
        exit(1);
    }
    if (code = krb5_cc_initialize(kcontext, ccache, creds.client)) {
        com_err (argv[0], code, "when initializing cache %s",
                 cache_name?cache_name:"");
        exit(1);
    }
    if (code = krb5_cc_store_cred(kcontext, ccache, &creds)) {
        com_err (argv[0], code, "while storing credentials");
        exit(1);
    }
    krb5_cc_close(kcontext, ccache);
    krb5_free_context(kcontext);
}

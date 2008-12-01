/*
 * $Header$
 *
 * Copyright 2008 Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
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
 */

#include "string.h"
#include <stdlib.h>
#include <malloc.h>

#include "tls.h"

struct tspdata* new_tspdata(char* uuid, time_t sst) {
    struct tspdata* p   = (struct tspdata*)malloc(sizeof(struct tspdata));
    if (p) {
        memset(p, 0, sizeof(struct tspdata));
        p->_sst = sst;
        if (uuid) {strncpy(p->_uuid, uuid, UUID_SIZE-1);}
        }
    return p;
    }

void delete_tspdata(struct tspdata* p) {
    if (p)          free(p);
    }

void tspdata_setUUID(struct tspdata* p, unsigned char __RPC_FAR* uuidString) {
    strncpy(p->_uuid, uuidString, UUID_SIZE-1);
    };

void         tspdata_setConnected (struct tspdata* p, BOOL b)           {p->_CCAPI_Connected = b;}

void         tspdata_setReplyEvent(struct tspdata* p, HANDLE h)         {p->_replyEvent = h;}

void         tspdata_setRpcAState (struct tspdata* p, RPC_ASYNC_STATE* rpcState) {
    p->_rpcState = rpcState;}

void         tspdata_setSST       (struct tspdata* p, time_t t)         {p->_sst = t;}

void         tspdata_setStream    (struct tspdata* p, k5_ipc_stream s)   {p->_stream = s;}


BOOL         tspdata_getConnected (const struct tspdata* p)         {return p->_CCAPI_Connected;}

HANDLE       tspdata_getReplyEvent(const struct tspdata* p)         {return p->_replyEvent;}

time_t       tspdata_getSST       (const struct tspdata* p)         {return p->_sst;}

k5_ipc_stream tspdata_getStream    (const struct tspdata* p)         {return p->_stream;}

char*        tspdata_getUUID      (const struct tspdata* p)         {return p->_uuid;}

RPC_ASYNC_STATE* tspdata_getRpcAState (const struct tspdata* p)     {return p->_rpcState;}

BOOL WINAPI PutTspData(DWORD dwTlsIndex, struct tspdata* dw) {
    LPVOID              lpvData; 
    struct tspdata**    pData;  // The stored memory pointer 

    // Retrieve a data pointer for the current thread:
    lpvData = TlsGetValue(dwTlsIndex); 

    // If NULL, allocate memory for the TLS slot for this thread:
    if (lpvData == NULL) {
        lpvData = (LPVOID) LocalAlloc(LPTR, sizeof(struct tspdata)); 
        if (lpvData == NULL)                      return FALSE;
        if (!TlsSetValue(dwTlsIndex, lpvData))    return FALSE;
        }

    pData = (struct tspdata**) lpvData; // Cast to my data type.
    // In this example, it is only a pointer to a DWORD
    // but it can be a structure pointer to contain more complicated data.

    (*pData) = dw;
    return TRUE;
    }

BOOL WINAPI GetTspData(DWORD dwTlsIndex, struct tspdata**  pdw) {
    struct tspdata*  pData;      // The stored memory pointer 

    pData = (struct tspdata*)TlsGetValue(dwTlsIndex); 
    if (pData == NULL) return FALSE;
    (*pdw) = pData;
    return TRUE;
    }



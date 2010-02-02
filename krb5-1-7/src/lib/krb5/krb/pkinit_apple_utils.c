/*
 * Copyright (c) 2004-2008 Apple Inc.  All Rights Reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Apple Inc. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Apple Inc. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

/*
 * pkinit_apple_utils.c - PKINIT utilities, Mac OS X version
 *
 * Created 19 May 2004 by Doug Mitchell at Apple.
 */
 
#if APPLE_PKINIT

#include "pkinit_apple_utils.h"
#include "pkinit_asn1.h"
#include <sys/errno.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <Security/Security.h>

/* 
 * Cruft needed to attach to a module
 */
static CSSM_VERSION vers = {2, 0};
static const CSSM_GUID testGuid = { 0xFADE, 0, 0, { 1,2,3,4,5,6,7,0 }};

/*
 * Standard app-level memory functions required by CDSA.
 */
static void * cuAppMalloc (CSSM_SIZE size, void *allocRef) {
	return( malloc(size) );
}

static void cuAppFree (void *mem_ptr, void *allocRef) {
	free(mem_ptr);
 	return;
}

static void * cuAppRealloc (void *ptr, CSSM_SIZE size, void *allocRef) {
	return( realloc( ptr, size ) );
}

static void * cuAppCalloc (uint32 num, CSSM_SIZE size, void *allocRef) {
	return( calloc( num, size ) );
}

static CSSM_API_MEMORY_FUNCS memFuncs = {
	cuAppMalloc,
	cuAppFree,
	cuAppRealloc,
 	cuAppCalloc,
 	NULL
};

/*
 * Init CSSM; returns CSSM_FALSE on error. Reusable.
 */
static CSSM_BOOL cssmInitd = CSSM_FALSE;

static CSSM_BOOL cuCssmStartup()
{
    CSSM_RETURN  crtn;
    CSSM_PVC_MODE pvcPolicy = CSSM_PVC_NONE;
    
    if(cssmInitd) {
	return CSSM_TRUE;
    }  
    crtn = CSSM_Init (&vers, 
	CSSM_PRIVILEGE_SCOPE_NONE,
	&testGuid,
	CSSM_KEY_HIERARCHY_NONE,
	&pvcPolicy,
	NULL /* reserved */);
    if(crtn != CSSM_OK) 
    {
	return CSSM_FALSE;
    }
    else {
	cssmInitd = CSSM_TRUE;
	return CSSM_TRUE;
    }
}

CSSM_CL_HANDLE pkiClStartup(void)
{
    CSSM_CL_HANDLE clHand;
    CSSM_RETURN crtn;
    
    if(cuCssmStartup() == CSSM_FALSE) {
	return 0;
    }
    crtn = CSSM_ModuleLoad(&gGuidAppleX509CL,
	CSSM_KEY_HIERARCHY_NONE,
	NULL,			/* eventHandler */
	NULL);			/* AppNotifyCallbackCtx */
    if(crtn) {
	return 0;
    }
    crtn = CSSM_ModuleAttach (&gGuidAppleX509CL,
	&vers,
	&memFuncs,		    /* memFuncs */
	0,			    /* SubserviceID */
	CSSM_SERVICE_CL,	    /* SubserviceFlags - Where is this used? */
	0,			    /* AttachFlags */
	CSSM_KEY_HIERARCHY_NONE,
	NULL,			    /* FunctionTable */
	0,			    /* NumFuncTable */
	NULL,			    /* reserved */
	&clHand);
    if(crtn) {
	return 0;
    }
    else {
	return clHand;
    }
}

CSSM_RETURN pkiClDetachUnload(
	CSSM_CL_HANDLE  clHand)
{
    CSSM_RETURN crtn = CSSM_ModuleDetach(clHand);
    if(crtn) {
	return crtn;
    }
    return CSSM_ModuleUnload(&gGuidAppleX509CL, NULL, NULL);
}

/*
 * CSSM_DATA <--> krb5_ui_4
 */
krb5_error_code pkiDataToInt(
    const CSSM_DATA *cdata, 
    krb5_int32       *i)	/* RETURNED */
{
    krb5_ui_4 len;
    krb5_int32 rtn = 0;
    krb5_ui_4 dex;
    uint8 *cp = NULL;
    
    if((cdata->Length == 0) || (cdata->Data == NULL)) {
	*i = 0;
	return 0;
    }
    len = cdata->Length;
    if(len > sizeof(krb5_int32)) {
	return ASN1_BAD_LENGTH;
    }
    
    cp = cdata->Data;
    for(dex=0; dex<len; dex++) {
	rtn = (rtn << 8) | *cp++;
    }
    *i = rtn;
    return 0;
}

krb5_error_code pkiIntToData(
    krb5_int32	    num,
    CSSM_DATA       *cdata,
    SecAsn1CoderRef coder)
{
    krb5_ui_4 unum = (krb5_ui_4)num;
    uint32 len = 0;
    uint8 *cp = NULL;
    unsigned i;
    
    if(unum < 0x100) {
	len = 1;
    }
    else if(unum < 0x10000) {
	len = 2;
    }
    else if(unum < 0x1000000) {
	len = 3;
    }
    else {
	len = 4;
    }
    if(SecAsn1AllocItem(coder, cdata, len)) {
	return ENOMEM;
    }
    cp = &cdata->Data[len - 1];
    for(i=0; i<len; i++) {
	*cp-- = unum & 0xff;
	unum >>= 8;
    }
    return 0;
}

/*
 * raw data --> krb5_data
 */
krb5_error_code pkiDataToKrb5Data(
    const void *data,
    unsigned dataLen,
    krb5_data *kd)
{
    assert(data != NULL);
    assert(kd != NULL);
    kd->data = (char *)malloc(dataLen);
    if(kd->data == NULL) {
	return ENOMEM;
    }
    kd->length = dataLen;
    memmove(kd->data, data, dataLen);
    return 0;
}

/* 
 * CSSM_DATA <--> krb5_data
 *
 * CSSM_DATA data is managed by a SecAsn1CoderRef; krb5_data data is mallocd.
 *
 * Both return nonzero on error.
 */
krb5_error_code pkiCssmDataToKrb5Data(
    const CSSM_DATA *cd, 
    krb5_data *kd)
{
    assert(cd != NULL);
    return pkiDataToKrb5Data(cd->Data, cd->Length, kd);
}

krb5_error_code pkiKrb5DataToCssm(
    const krb5_data *kd,
    CSSM_DATA       *cd,
    SecAsn1CoderRef coder)
{
    assert((cd != NULL) && (kd != NULL));
    if(SecAsn1AllocCopy(coder, kd->data, kd->length, cd)) {
	return ENOMEM;
    }
    return 0;
}

/* 
 * CFDataRef --> krb5_data, mallocing the destination contents.
 */
krb5_error_code pkiCfDataToKrb5Data(
    CFDataRef	    cfData,
    krb5_data	    *kd)	/* content mallocd and RETURNED */
{
    return pkiDataToKrb5Data(CFDataGetBytePtr(cfData),
	CFDataGetLength(cfData), kd);
}

krb5_boolean pkiCompareCssmData(
    const CSSM_DATA *d1,
    const CSSM_DATA *d2)
{
    if((d1 == NULL) || (d2 == NULL)) {
	return FALSE;
    }
    if(d1->Length != d2->Length) {
	return FALSE;
    }
    if(memcmp(d1->Data, d2->Data, d1->Length)) {
	return FALSE;
    }
    else {
	return TRUE;
    }
}

/* 
 * krb5_timestamp --> a mallocd string in generalized format
 */
krb5_error_code pkiKrbTimestampToStr(
    krb5_timestamp kts,
    char **str)		    /* mallocd and RETURNED */
{
    char *outStr = NULL;
    time_t gmt_time = kts;
    struct tm *utc = gmtime(&gmt_time);
    if (utc == NULL ||
	utc->tm_year > 8099 || utc->tm_mon > 11 ||
	utc->tm_mday > 31 || utc->tm_hour > 23 ||
	utc->tm_min > 59 || utc->tm_sec > 59) {
	return ASN1_BAD_GMTIME;
    }
    if (asprintf(&outStr, "%04d%02d%02d%02d%02d%02dZ",
		 utc->tm_year + 1900, utc->tm_mon + 1,
		 utc->tm_mday, utc->tm_hour, utc->tm_min, utc->tm_sec) < 0) {
	return ENOMEM;
    }
    *str = outStr;
    return 0;
}

krb5_error_code pkiTimeStrToKrbTimestamp(
    const char		*str,
    unsigned		len,
    krb5_timestamp      *kts)       /* RETURNED */
{
    char 	szTemp[5];
    unsigned 	x;
    unsigned 	i;
    char 	*cp;
    struct tm	tmp;
    time_t      t;
    
    if(len != 15) {
	return ASN1_BAD_LENGTH;
    }

    if((str == NULL) || (kts == NULL)) {
    	return KRB5_CRYPTO_INTERNAL;
    }
  	
    cp = (char *)str;
    memset(&tmp, 0, sizeof(tmp));
    
    /* check that all characters except last are digits */
    for(i=0; i<(len - 1); i++) {
	if ( !(isdigit(cp[i])) ) {
	    return ASN1_BAD_TIMEFORMAT;
	}
    }

    /* check last character is a 'Z' */
    if(cp[len - 1] != 'Z' )	{
	return ASN1_BAD_TIMEFORMAT;
    }
    
    /* YEAR */
    szTemp[0] = *cp++;
    szTemp[1] = *cp++;
    szTemp[2] = *cp++;
    szTemp[3] = *cp++;
    szTemp[4] = '\0';
    x = atoi( szTemp );
    /* by definition - tm_year is year - 1900 */
    tmp.tm_year = x - 1900;

    /* MONTH */
    szTemp[0] = *cp++;
    szTemp[1] = *cp++;
    szTemp[2] = '\0';
    x = atoi( szTemp );
    /* in the string, months are from 1 to 12 */
    if((x > 12) || (x <= 0)) {
	return ASN1_BAD_TIMEFORMAT;
    }
    /* in a tm, 0 to 11 */
    tmp.tm_mon = x - 1;

    /* DAY */
    szTemp[0] = *cp++;
    szTemp[1] = *cp++;
    szTemp[2] = '\0';
    x = atoi( szTemp );
    /* 1..31 */
    if((x > 31) || (x <= 0)) {
	return ASN1_BAD_TIMEFORMAT;
    }
    tmp.tm_mday = x;

    /* HOUR */
    szTemp[0] = *cp++;
    szTemp[1] = *cp++;
    szTemp[2] = '\0';
    x = atoi( szTemp );
    if((x > 23) || (x < 0)) {
	return ASN1_BAD_TIMEFORMAT;
    }
    tmp.tm_hour = x;

    /* MINUTE */
    szTemp[0] = *cp++;
    szTemp[1] = *cp++;
    szTemp[2] = '\0';
    x = atoi( szTemp );
    if((x > 59) || (x < 0)) {
	return ASN1_BAD_TIMEFORMAT;
    }
    tmp.tm_min = x;

    /* SECOND */
    szTemp[0] = *cp++;
    szTemp[1] = *cp++;
    szTemp[2] = '\0';
    x = atoi( szTemp );
    if((x > 59) || (x < 0)) {
	return ASN1_BAD_TIMEFORMAT;
    }
    tmp.tm_sec = x;
    t = timegm(&tmp);
    if(t == -1) {
	return ASN1_BAD_TIMEFORMAT;
    }
    *kts = t;
    return 0;
}

/*
 * How many items in a NULL-terminated array of pointers?
 */
unsigned pkiNssArraySize(
    const void **array)
{
    unsigned count = 0;
    if (array) {
	while (*array++) {
	    count++;
	}
    }
    return count;
}

#endif /* APPLE_PKINIT */

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
 * pkinit_apple_utils.h - PKINIT utilities, Mac OS X version
 *
 * Created 19 May 2004 by Doug Mitchell.
 */
 
#ifndef	_PKINIT_APPLE_UTILS_H_
#define _PKINIT_APPLE_UTILS_H_

#include <krb5/krb5.h>
#include <Security/SecAsn1Coder.h>
#include <Security/cssmapple.h>
#include <CoreFoundation/CoreFoundation.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PKI_DEBUG
#define PKI_DEBUG   0
#endif

#if	PKI_DEBUG

#include <stdio.h>

#define pkiDebug(args...)       printf(args)
#define pkiCssmErr(str, rtn)    cssmPerror(str, rtn)
#else
#define pkiDebug(args...)
#define pkiCssmErr(str, rtn)
#endif	/* PKI_DEBUG */

/*
 * Macros used to initialize a declared CSSM_DATA and krb5_data to zero/NULL values.
 */
#define INIT_CDATA(cd)  cd = {0, NULL}
#define INIT_KDATA(kd)  kd = {0, 0, NULL}

/* attach/detach to/from CL */
CSSM_RETURN pkiClDetachUnload(CSSM_CL_HANDLE  clHand);
CSSM_CL_HANDLE pkiClStartup(void);

/*
 * CSSM_DATA <--> krb5_ui_4
 */
krb5_error_code pkiDataToInt(
    const CSSM_DATA *cdata, 
    krb5_int32       *i);	/* RETURNED */

krb5_error_code pkiIntToData(
    krb5_int32	    num,
    CSSM_DATA       *cdata,     /* allocated in coder space and RETURNED */
    SecAsn1CoderRef coder);

/*
 * raw data --> krb5_data
 */
krb5_error_code pkiDataToKrb5Data(
    const void *data,
    unsigned dataLen,
    krb5_data *kd);		/* content mallocd and RETURNED */

/* 
 * CSSM_DATA <--> krb5_data
 *
 * CSSM_DATA data is managed by a SecAsn1CoderRef; krb5_data.data is mallocd.
 */
krb5_error_code pkiCssmDataToKrb5Data(
    const CSSM_DATA *cd, 
    krb5_data *kd);		/* content mallocd and RETURNED */


krb5_error_code pkiKrb5DataToCssm(
    const krb5_data *kd,
    CSSM_DATA       *cdata,     /* allocated in coder space and RETURNED */
    SecAsn1CoderRef coder);

/* 
 * CFDataRef --> krb5_data, mallocing the destination contents.
 */
krb5_error_code pkiCfDataToKrb5Data(
    CFDataRef	    cfData,
    krb5_data	    *kd);	/* content mallocd and RETURNED */
    
/*
 * Non-mallocing conversion between CSSM_DATA and krb5_data
 */
#define PKI_CSSM_TO_KRB_DATA(cd, kd)    \
    (kd)->data = (char *)(cd)->Data;	\
    (kd)->length = (cd)->Length;

#define PKI_KRB_TO_CSSM_DATA(kd, cd)    \
    (cd)->Data = (uint8 *)(kd)->data;	\
    (cd)->Length = (kd)->length;

/*
 * Compare to CSSM_DATAs. Return TRUE if they're the same else FALSE.
 */
krb5_boolean pkiCompareCssmData(
    const CSSM_DATA *d1,
    const CSSM_DATA *d2);

/* 
 * krb5_timestamp <--> a mallocd string in generalized format
 */
krb5_error_code pkiKrbTimestampToStr(
    krb5_timestamp      kts,
    char		**str);		/* mallocd and RETURNED */

krb5_error_code pkiTimeStrToKrbTimestamp(
    const char		*str,
    unsigned		len,
    krb5_timestamp      *kts);		/* RETURNED */

/*
 * How many items in a NULL-terminated array of pointers?
 */
unsigned pkiNssArraySize(
    const void **array);

#ifdef __cplusplus
}
#endif

#endif  /* _PKINIT_APPLE_UTILS_H_ */

/*
 * include/krb5/safepriv.h
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * #defines for SAFE and PRIV message options.
 */


#ifndef KRB5_SAFE_PRIV__
#define KRB5_SAFE_PRIV__

#define KRB5_AUTH_CONTEXT_DO_TIME       0x00000001
#define KRB5_AUTH_CONTEXT_RET_TIME      0x00000002
#define KRB5_AUTH_CONTEXT_DO_SEQUENCE   0x00000004
#define KRB5_AUTH_CONTEXT_RET_SEQUENCE  0x00000008
 
typedef struct krb5_replay_data { 
    krb5_timestamp      timestamp; 
    krb5_int32          usec;
    krb5_int32          seq; 
} krb5_replay_data;

#endif /* KRB5_SAFE_PRIV__ */

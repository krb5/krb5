/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Declarations for policy.c
 */

#include <krb5/copyright.h>

#ifndef __KRB5_KDC_POLICY__
#define __KRB5_KDC_POLICY__

extern krb5_boolean against_postdate_policy PROTOTYPE((krb5_timestamp));
extern krb5_boolean against_flag_policy_as PROTOTYPE((krb5_as_req *));
extern krb5_boolean against_flag_policy_tgs PROTOTYPE((krb5_tgs_req *));

#endif /* __KRB5_KDC_POLICY__ */

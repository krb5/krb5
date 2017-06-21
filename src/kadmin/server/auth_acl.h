/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* kadmin/server/auth_acl.h */
/*
 * Copyright 1995-2004, 2007, 2008 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifndef SERVER_ACL_H__
#define SERVER_ACL_H__

/*
 * Access control bits.
 */
#define ACL_ADD                 1
#define ACL_DELETE              2
#define ACL_MODIFY              4
#define ACL_CHANGEPW            8
/* #define ACL_CHANGE_OWN_PW    16 */
#define ACL_INQUIRE             32
#define ACL_EXTRACT             64
#define ACL_LIST                128
#define ACL_SETKEY              256
#define ACL_IPROP               512

#define ACL_ALL_MASK            (ACL_ADD        |       \
                                 ACL_DELETE     |       \
                                 ACL_MODIFY     |       \
                                 ACL_CHANGEPW   |       \
                                 ACL_INQUIRE    |       \
                                 ACL_LIST       |       \
                                 ACL_IPROP      |       \
                                 ACL_SETKEY)

struct kadm5_auth_restrictions {
    long mask;
    krb5_flags require_attrs;
    krb5_flags forbid_attrs;
    krb5_deltat princ_lifetime;
    krb5_deltat pw_lifetime;
    krb5_deltat max_life;
    krb5_deltat max_renewable_life;
    char *policy;
};

krb5_error_code acl_init(krb5_context context, const char *acl_file);
void acl_finish(krb5_context);
krb5_boolean acl_check(krb5_context context, krb5_const_principal client,
                       uint32_t op, krb5_const_principal target,
                       struct kadm5_auth_restrictions **rs_out);
krb5_error_code acl_impose_restrictions(krb5_context context,
                                        kadm5_principal_ent_rec *rec,
                                        long *mask,
                                        struct kadm5_auth_restrictions *rs);

#endif  /* SERVER_ACL_H__ */

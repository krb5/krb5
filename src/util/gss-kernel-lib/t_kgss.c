/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* util/gss-kernel-lib/t_kgss.c - Kernel GSS library test program */
/*
 * Copyright (C) 2011 by the Massachusetts Institute of Technology.
 * All rights reserved.
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

int
main(int argc, char **argv)
{
    krb5_gss_wrap_iov();
    krb5_gss_wrap_iov_length();
    krb5_gss_wrap();
    krb5_gss_unwrap();
    krb5_gss_unwrap_iov();
    krb5_gss_get_mic();
    krb5_gss_verify_mic();
    return 0;
}

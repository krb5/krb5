/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* prototype/prototype.c */
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

/*
 * pkinit_kdf_test.c -- Structures and constants for implementation of
 * pkinit algorithm agility.  Includes definitions of algorithm identifiers
 * for SHA-1, SHA-256 and SHA-512.
 */

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <unistd.h>
#include <dirent.h>

#include "k5-platform.h"
#include "krb5.h"
#include "k5-int-pkinit.h"

#include "pkinit.h"
#include "pkinit_crypto.h"

/* statically declare OID constants for all three algorithms */
const krb5_octet krb5_pkinit_sha1_oid[10] =
{0x2B,0x06,0x01,0x05,0x02,0x03,0x06,0x01};
const size_t krb5_pkinit_sha1_oid_len = 8;
const krb5_octet krb5_pkinit_sha256_oid[10] =
{0x2B,0x06,0x01,0x05,0x02,0x03,0x06,0x02};
const size_t krb5_pkinit_sha256_oid_len = 8;
const krb5_octet krb5_pkinit_sha512_oid [10] =
{0x2B,0x06,0x01,0x05,0x02,0x03,0x06,0x03};
const size_t krb5_pkinit_sha512_oid_len = 8;

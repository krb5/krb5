/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* util/support/k5buf-int.h */
/*
 * Copyright 2008 Massachusetts Institute of Technology.
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

/* Internal declarations for the k5buf string buffer module */

#ifndef K5BUF_INT_H
#define K5BUF_INT_H

#include "k5-platform.h"
#include "k5-buf.h"

/* The k5buf structure has funny field names to discourage callers
   from violating the abstraction barrier.  Define less funny names
   for them here. */
#define buftype xx_buftype
#define data xx_data
#define space xx_space
#define len xx_len

#define DYNAMIC_INITIAL_SIZE 128
#define SPACE_MAX (SIZE_MAX / 2) /* rounds down, since SIZE_MAX is odd */

/* Buffer type values. */
enum { BUFTYPE_FIXED, BUFTYPE_DYNAMIC, BUFTYPE_ERROR };

#endif /* K5BUF_INT_H */

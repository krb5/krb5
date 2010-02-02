/*
 * $Header$
 *
 * Copyright 2006 Massachusetts Institute of Technology.
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

#ifndef TEST_KIM_COMMON_H
#define TEST_KIM_COMMON_H

#include <kim/kim.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct kim_test_state_d {
    const char *test_name;
    int global_fail_count;
    int test_fail_count;
} *kim_test_state_t;

int test_init (kim_test_state_t *out_state);

int test_cleanup (kim_test_state_t io_state);

void start_test (kim_test_state_t  in_state,
                 const char       *in_test_name);

void end_test (kim_test_state_t in_state);

void fail_if_error (kim_test_state_t  in_state, 
                    const char       *in_function,
                    kim_error       in_err, 
                    const char       *in_format,
                    ...)
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
__attribute__ ((__format__ (__printf__, 4, 5)))
#endif
;

void log_failure (kim_test_state_t  in_state, 
                  const char       *in_format,
                  ...)
#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)
__attribute__ ((__format__ (__printf__, 2, 3)))
#endif
;

#endif /* TEST_KIM_COMMON_H */

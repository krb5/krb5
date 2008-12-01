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

#ifndef TEST_KIM_IDENTITY_H
#define TEST_KIM_IDENTITY_H

#include "test_kim_common.h"

void test_kim_identity_create_from_krb5_principal (kim_test_state_t state);

void test_kim_identity_create_from_string (kim_test_state_t state);

void test_kim_identity_create_from_components (kim_test_state_t state);

void test_kim_identity_copy (kim_test_state_t state);

void test_kim_identity_compare (kim_test_state_t state);

void test_kim_identity_get_display_string (kim_test_state_t state);

void test_kim_identity_get_realm (kim_test_state_t state);

void test_kim_identity_get_number_of_components (kim_test_state_t state);

void test_kim_identity_get_component_at_index (kim_test_state_t state);

void test_kim_identity_get_krb5_principal (kim_test_state_t state);

#endif /* TEST_KIM_IDENTITY_H */

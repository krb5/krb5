/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Default credentials cache determination.  This is a separate file
 * so that the user can more easily override it.
 */

#include "file/fcc.h"
#include "stdio/scc.h"

krb5_cc_ops *krb5_cc_dfl_ops = &krb5_cc_file_ops;

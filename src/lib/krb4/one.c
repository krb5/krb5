/*
 * one.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "conf.h"

/*
 * definition of variable set to 1.
 * used in krb_conf.h to determine host byte order.
 */

#ifndef HOST_BYTE_ORDER
const int krbONE = 1;
#endif

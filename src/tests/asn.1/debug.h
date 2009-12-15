/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef __DEBUG_H__
#define __DEBUG_H__

/*
  assert utility macro for test programs:
  If the predicate (pred) is true, then
  OK: <message> is printed.  Otherwise,
  ERROR: <message> is printed.

  message should be a printf format string.
*/

#include <stdio.h>

#define test(pred,message)                      \
    if(pred) printf("OK: ");                    \
    else { printf("ERROR: "); error_count++; }  \
    printf(message);

#endif

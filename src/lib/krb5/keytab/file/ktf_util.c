/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * This function contains utilities for the file based implementation of 
 * the keytab.  There are no public functions in this file.
 *
 * This file is the only one that has knowledge of the format of a
 * keytab file.
 *
 * The format is as follows:
 * 
 * principal vno key
 * principal vno key
 * ....
 *
 * There are no separators between fields of an entry or between entries.
 * A principal is a length-encoded array of length-encoded strings.  The
 * length is a krb5_length XXX in each case.  The specific format, then, is 
 * multiple entries concatinated with no separators.  An entry has this 
 * exact format:
 *
 * sizeof(krb5_length) bytes for number of components in the principal; 
 * then, each component listed in ordser.
 * For each component, sizeof(krb5_length) bytes for the number of bytes
 * in the component, followed by the component.
 * sizeof(krb5_kvno) bytes for the key version number
 * sizeof(krb5_key_block) bytes for the key
 *
 * Extra garbage at the end of a keytab will be not be searched for, but
 * 
 * 
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_ktf_util_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>

#include "ktfile.h"


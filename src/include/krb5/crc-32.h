/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Definitions for the CRC-32 checksum
 */

#include <krb5/copyright.h>

#ifndef KRB5_CRC32__
#define KRB5_CRC32__

#define CRC32_CKSUMTYPE	1

#define CRC32_CKSUM_LENGTH	(4*sizeof(krb5_octet))

extern krb5_checksum_entry crc32_cksumtable_entry;

#endif /* KRB5_CRC32__ */

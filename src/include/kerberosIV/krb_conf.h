/*
 * include/kerberosIV/krb_conf.h
 *
 * Copyright 1988, 1994 by the Massachusetts Institute of Technology.
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
 * 
 * This file contains configuration information for the Kerberos library
 * which is machine specific; currently, this file contains
 * configuration information for the vax, the "ibm032" (RT), and the
 * "PC8086" (IBM PC). 
 *
 * Note:  cross-compiled targets must appear BEFORE their corresponding
 * cross-compiler host.  Otherwise, both will be defined when running
 * the native compiler on the programs that construct cross-compiled
 * sources. 
 */

#ifndef KRB_CONF_DEFS
#define KRB_CONF_DEFS

/* Byte ordering */
extern int krbONE;
#define		HOST_BYTE_ORDER	(* (char *) &krbONE)
#define		MSB_FIRST		0	/* 68000, IBM RT/PC */
#define		LSB_FIRST		1	/* Vax, PC8086 */

#endif /* KRB_CONF_DEFS */

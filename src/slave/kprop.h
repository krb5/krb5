/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 */

#define KPROP_SERVICE_NAME "host"
#define KPROP_SRVTAB "/etc/srvtab"
#define TGT_SERVICE_NAME "krbtgt"
#define KPROP_SERVICE "krb5_prop"
#define KPROP_DEFAULT_FILE "/krb5/slave_datatrans"
#define KPROPD_DEFAULT_FILE "/krb5/from_master"
#define KPROP_CKSUMTYPE CKSUMTYPE_RSA_MD4_DES
#define KPROPD_DEFAULT_KDB5_EDIT "/krb5/bin/kdb5_edit"
#define KPROPD_DEFAULT_KRB_DB "/krb5/principal"
#define KPROPD_ACL_FILE "/krb5/kpropd.acl"

#define KPROP_PROT_VERSION "kprop5_01"

#define KPROP_BUFSIZ 32768


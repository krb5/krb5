/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 */

#define KPROP_SERVICE_NAME "rcmd"
#define KPROP_SRVTAB "/etc/srvtab"
#define TGT_SERVICE_NAME "krbtgt"
#define KPROP_SERVICE "krb5_prop"
#define KPROP_DEFAULT_FILE "/krb5/slave_datatrans"
#define KPROPD_DEFAULT_FILE "/krb5/from_master"
#define KPROP_CKSUMTYPE CKSUMTYPE_RSA_MD4_DES
#define KPROPD_DEFAULT_KDB5_EDIT "/krb5/bin/kdb5_edit"
#define KPROPD_DEFAULT_KRB_DB "/krb5/principal"

#define KPROP_PROT_VERSION "kprop5_01"

#define KPROP_BUFSIZ 32768

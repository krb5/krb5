/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Definition of default configuration parameters.
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_config_fn_c [] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/copyright.h>
#include <krb5/osconf.h>


char *krb5_config_file = DEFAULT_CONFIG_FILENAME;
char *krb5_trans_file = DEFAULT_TRANS_FILENAME;

#ifdef KRB5_USE_INET
char *krb5_kdc_udp_portname = KDC_PORTNAME;
#endif

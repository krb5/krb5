/*
Copyright 1990, Daniel J. Bernstein. All rights reserved.

Please address any questions or comments to the author at brnstnd@acf10.nyu.edu.
*/

#ifndef KRB5_RC_H
#define KRB5_RC_H
#include "krb5/krb5.h"

typedef struct krb5_inRC
 {
  struct krb5_rc_type *ops;
  void *data;
 }
*krb5_RC;

struct krb5_rc_type
 {
  char *type;
  krb5_error_code (*init)PROTOTYPE((krb5_RC,krb5_deltat)); /* i.e., create */
  krb5_error_code (*recover)PROTOTYPE((krb5_RC)); /* i.e., open */
  krb5_error_code (*destroy)PROTOTYPE((krb5_RC));
  krb5_error_code (*close)PROTOTYPE((krb5_RC));
  krb5_error_code (*store)PROTOTYPE((krb5_RC,krb5_tkt_authent *));
  krb5_error_code (*expunge)PROTOTYPE((krb5_RC));
  krb5_error_code (*get_span)PROTOTYPE((krb5_RC,krb5_deltat *));
  char *(*get_name)PROTOTYPE((krb5_RC));
  krb5_error_code (*resolve)PROTOTYPE((krb5_RC *,char *name));
 }
;

krb5_error_code krb5_rc_register_type PROTOTYPE((struct krb5_rc_type *ops));
krb5_error_code krb5_rc_resolve_type PROTOTYPE((krb5_RC *id,char *type));
char *krb5_rc_get_type PROTOTYPE((krb5_RC id));
char *krb5_rc_default_type PROTOTYPE((void));
char *krb5_rc_default_name PROTOTYPE((void));

#endif

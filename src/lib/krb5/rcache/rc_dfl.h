/*
Copyright 1990, Daniel J. Bernstein. All rights reserved.

Please address any questions or comments to the author at brnstnd@acf10.nyu.edu.
*/

#ifndef KRB5_RC_DFL_H
#define KRB5_RC_DFL_H
#include "krb5/krb5.h"
#include "rc_base.h"

struct krb5_rc_type krb5_rc_dfl_ops; /* initialized to the following */

krb5_error_code krb5_rc_dfl_init PROTOTYPE((krb5_RC,krb5_deltat));
krb5_error_code krb5_rc_dfl_recover PROTOTYPE((krb5_RC)); 
krb5_error_code krb5_rc_dfl_destroy PROTOTYPE((krb5_RC));
krb5_error_code krb5_rc_dfl_close PROTOTYPE((krb5_RC));
krb5_error_code krb5_rc_dfl_store PROTOTYPE((krb5_RC,krb5_tkt_authent *));
krb5_error_code krb5_rc_dfl_expunge PROTOTYPE((krb5_RC));
krb5_error_code krb5_rc_dfl_get_span PROTOTYPE((krb5_RC,krb5_deltat *));
char *krb5_rc_dfl_get_name PROTOTYPE((krb5_RC));
krb5_error_code krb5_rc_dfl_resolve PROTOTYPE((krb5_RC *,char *name));

#endif

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

struct	retdata {
     krb5_context context;
     FILE    *fp;
     int	    count;
     int	    ovsec_compat;
};

osa_adb_ret_t	export_principal(struct retdata *, kadm5_config_params *);
osa_adb_ret_t	export_policy(struct retdata *d, osa_adb_policy_t);

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 * 
 * $Log$
 * Revision 1.6  2001/02/18 23:00:08  epeisach
 * 	* server_internal.h: Add prototype for
 *         krb5_free_key_data_contents() which really should be in libkdb.
 *
 * 	* kadm_rpc_xdr.c: Include krb5/admin_xdr.h for prototypes.
 *
 * 	* kadm_rpc.h: Add prototypes for client and server stub
 *         functions. Server functions renamed to have _svc appended.
 *
 * 	* alt_prof.c: Clean up warnings. Do not shadow index() with local
 *         variable.
 *
 * 	* admin_xdr.h: Add prototypes for xdr_nulltype(), xdr_krb5_ui_4(),
 *         xdr_krb5_int16(), xdr_krb5_key_data_nocontents(),
 *         xdr_krb5_key_salt_tuple(), xdr_krb5_tl_data(),
 *         xdr_kadm5_principal_ent_rec_v1(), xdr_cprinc3_arg(),
 *         xdr_generic_ret(0, xdr_chpass3_arg(), xdr_setv4key_arg(),
 *         xdr_setkey_arg(), xdr_setkey3_arg(), xdr_chrand3_arg(),
 *         xdr_gprincs_arg(), xdr_grpincs_ret(), xdr_gpols_arg(),
 *         xdr_gpols_ret(), xdr_getprivs_ret(), xdr_krb5_salttype().
 *
 * 	* admin_internal.h: Add prototype for _kadm5_check_handle().
 *
 * 	* admin.h: Add prototypes for kadm5_free_config_params(),
 *         kadm5_decrypt_key(), ovsec_kadm_free_name_list().
 *
 * 	* adb.h: Add prototypes for xdr_osa_pw_hist_ent(),
 *         xdr_krb5_key_data(), osa_adb_rename_db(),
 *         osa_adb_rename_policy_db().
 *
 * Revision 1.5  1996/07/22 20:35:33  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.4.4.1  1996/07/18 03:08:25  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.4.2.1  1996/06/20  02:16:37  marc
 * File added to the repository on a branch
 *
 * Revision 1.4  1996/05/30  16:36:34  bjaspan
 * finish updating to kadm5 naming (oops)
 *
 * Revision 1.3  1996/05/22 00:28:19  bjaspan
 * rename to kadm5
 *
 * Revision 1.2  1996/05/12 06:30:10  marc
 *  - fixup includes and data types to match beta6
 *
 * Revision 1.1  1993/11/09  04:06:01  shanzer
 * Initial revision
 *
 */

#include    <kadm5/admin.h>
#include    "kadm_rpc.h"

bool_t      xdr_ui_4(XDR *xdrs, krb5_ui_4 *objp);
bool_t	    xdr_nullstring(XDR *xdrs, char **objp);
bool_t      xdr_nulltype(XDR *xdrs, void **objp, xdrproc_t proc);
bool_t	    xdr_krb5_timestamp(XDR *xdrs, krb5_timestamp *objp);
bool_t	    xdr_krb5_kvno(XDR *xdrs, krb5_kvno *objp);
bool_t	    xdr_krb5_deltat(XDR *xdrs, krb5_deltat *objp);
bool_t	    xdr_krb5_flags(XDR *xdrs, krb5_flags *objp);
bool_t      xdr_krb5_ui_4(XDR *xdrs, krb5_ui_4 *objp);
bool_t      xdr_krb5_int16(XDR *xdrs, krb5_int16 *objp);
bool_t      xdr_krb5_key_data_nocontents(XDR *xdrs, krb5_key_data *objp);
bool_t      xdr_krb5_key_salt_tuple(XDR *xdrs, krb5_key_salt_tuple *objp);
bool_t      xdr_krb5_tl_data(XDR *xdrs, krb5_tl_data **tl_data_head);
bool_t	    xdr_kadm5_ret_t(XDR *xdrs, kadm5_ret_t *objp);
bool_t      xdr_kadm5_principal_ent_rec_v1(XDR *xdrs, kadm5_principal_ent_rec *objp);
bool_t	    xdr_kadm5_principal_ent_rec(XDR *xdrs, kadm5_principal_ent_rec *objp);
bool_t	    xdr_kadm5_policy_ent_rec(XDR *xdrs, kadm5_policy_ent_rec *objp);
bool_t	    xdr_kadm5_policy_ent_t(XDR *xdrs, kadm5_policy_ent_t *objp);
bool_t	    xdr_kadm5_principal_ent_t(XDR *xdrs, kadm5_principal_ent_t *objp);
bool_t	    xdr_cprinc_arg(XDR *xdrs, cprinc_arg *objp);
bool_t      xdr_cprinc3_arg(XDR *xdrs, cprinc3_arg *objp);
bool_t      xdr_generic_ret(XDR *xdrs, generic_ret *objp);
bool_t	    xdr_dprinc_arg(XDR *xdrs, dprinc_arg *objp);
bool_t	    xdr_mprinc_arg(XDR *xdrs, mprinc_arg *objp);
bool_t	    xdr_rprinc_arg(XDR *xdrs, rprinc_arg *objp);
bool_t	    xdr_chpass_arg(XDR *xdrs, chpass_arg *objp);
bool_t      xdr_chpass3_arg(XDR *xdrs, chpass3_arg *objp);
bool_t      xdr_setv4key_arg(XDR *xdrs, setv4key_arg *objp);
bool_t      xdr_setkey_arg(XDR *xdrs, setkey_arg *objp);
bool_t      xdr_setkey3_arg(XDR *xdrs, setkey3_arg *objp);
bool_t	    xdr_chrand_arg(XDR *xdrs, chrand_arg *objp);
bool_t      xdr_chrand3_arg(XDR *xdrs, chrand3_arg *objp);
bool_t	    xdr_chrand_ret(XDR *xdrs, chrand_ret *objp);
bool_t	    xdr_gprinc_arg(XDR *xdrs, gprinc_arg *objp);
bool_t      xdr_gprinc_ret(XDR *xdrs, gprinc_ret *objp);
bool_t	    xdr_gprincs_arg(XDR *xdrs, gprincs_arg *objp);
bool_t      xdr_gprincs_ret(XDR *xdrs, gprincs_ret *objp);
bool_t	    xdr_cpol_arg(XDR *xdrs, cpol_arg *objp);
bool_t	    xdr_dpol_arg(XDR *xdrs, dpol_arg *objp);
bool_t	    xdr_mpol_arg(XDR *xdrs, mpol_arg *objp);
bool_t	    xdr_gpol_arg(XDR *xdrs, gpol_arg *objp);
bool_t	    xdr_gpol_ret(XDR *xdrs, gpol_ret *objp);
bool_t      xdr_gpols_arg(XDR *xdrs, gpols_arg *objp);
bool_t      xdr_gpols_ret(XDR *xdrs, gpols_ret *objp);
bool_t      xdr_getprivs_ret(XDR *xdrs, getprivs_ret *objp);
bool_t	    xdr_krb5_principal(XDR *xdrs, krb5_principal *objp);
bool_t	    xdr_krb5_octet(XDR *xdrs, krb5_octet *objp);
bool_t	    xdr_krb5_int32(XDR *xdrs, krb5_int32 *objp);
bool_t	    xdr_krb5_enctype(XDR *xdrs, krb5_enctype *objp);
bool_t      xdr_krb5_salttype(XDR *xdrs, krb5_int32 *objp);
bool_t	    xdr_krb5_keyblock(XDR *xdrs, krb5_keyblock *objp);

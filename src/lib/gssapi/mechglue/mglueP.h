/* #ident  "@(#)mglueP.h 1.2     96/01/18 SMI" */

/*
 * This header contains the private mechglue definitions.
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _GSS_MECHGLUEP_H
#define _GSS_MECHGLUEP_H

#include "mechglue.h"

/*
 * Array of context IDs typed by mechanism OID
 */
typedef struct gss_union_ctx_id_t {
	gss_OID			mech_type;
	gss_ctx_id_t		internal_ctx_id;
} gss_union_ctx_id_desc, *gss_union_ctx_id_t;

/*
 * Generic GSSAPI names.  A name can either be a generic name, or a
 * mechanism specific name....
 */
typedef struct gss_union_name_t {
	gss_OID			name_type;
	gss_buffer_t		external_name;
	/*
	 * These last two fields are only filled in for mechanism
	 * names.
	 */
	gss_OID			mech_type;
	gss_name_t		mech_name;
} gss_union_name_desc, *gss_union_name_t;

/*
 * Structure for holding list of mechanism-specific name types
 */
typedef struct gss_mech_spec_name_t {
    gss_OID	name_type;
    gss_OID	mech;
    struct gss_mech_spec_name_t	*next, *prev;
} gss_mech_spec_name_desc, *gss_mech_spec_name;

/*
 * Credential auxiliary info, used in the credential structure
 */
typedef struct gss_union_cred_auxinfo {
	gss_buffer_desc		name;
	gss_OID			name_type;
	time_t			creation_time;
	OM_uint32		time_rec;
	int			cred_usage;
} gss_union_cred_auxinfo;

/*
 * Set of Credentials typed on mechanism OID
 */
typedef struct gss_union_cred_t {
	int			count;
	gss_OID			mechs_array;
	gss_cred_id_t *		cred_array;
	gss_union_cred_auxinfo	auxinfo;
} gss_union_cred_desc, *gss_union_cred_t;
 
/********************************************************/
/* The Mechanism Dispatch Table -- a mechanism needs to */
/* define one of these and provide a function to return */
/* it to initialize the GSSAPI library                  */

/*
 * This is the definition of the mechs_array struct, which is used to
 * define the mechs array table. This table is used to indirectly
 * access mechanism specific versions of the gssapi routines through
 * the routines in the glue module (gssd_mech_glue.c)
 *
 * This contants all of the functions defined in gssapi.h except for
 * gss_release_buffer() and gss_release_oid_set(), which I am
 * assuming, for now, to be equal across mechanisms.  
 */
 
typedef struct gss_config {
    gss_OID_desc    mech_type;
    void *	    context;
    OM_uint32       (*gss_acquire_cred)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_name_t,		/* desired_name */
		    OM_uint32,		/* time_req */
		    gss_OID_set,	/* desired_mechs */
		    int,		/* cred_usage */
		    gss_cred_id_t*,	/* output_cred_handle */
		    gss_OID_set*,	/* actual_mechs */
		    OM_uint32*		/* time_rec */
		    );
    OM_uint32       (*gss_release_cred)
	(
		    void*,		/* context */		       
		    OM_uint32*,		/* minor_status */
		    gss_cred_id_t*	/* cred_handle */
		    );
    OM_uint32       (*gss_init_sec_context)
	(
		    void*,			/* context */
		    OM_uint32*,			/* minor_status */
		    gss_cred_id_t,		/* claimant_cred_handle */
		    gss_ctx_id_t*,		/* context_handle */
		    gss_name_t,			/* target_name */
		    gss_OID,			/* mech_type */
		    OM_uint32,			/* req_flags */
		    OM_uint32,			/* time_req */
		    gss_channel_bindings_t,	/* input_chan_bindings */
		    gss_buffer_t,		/* input_token */
		    gss_OID*,			/* actual_mech_type */
		    gss_buffer_t,		/* output_token */
		    OM_uint32*,			/* ret_flags */
		    OM_uint32*			/* time_rec */
		    );
    OM_uint32       (*gss_accept_sec_context)
	(
		    void*,			/* context */
		    OM_uint32*,			/* minor_status */
		    gss_ctx_id_t*,		/* context_handle */
		    gss_cred_id_t,		/* verifier_cred_handle */
		    gss_buffer_t,		/* input_token_buffer */
		    gss_channel_bindings_t,	/* input_chan_bindings */
		    gss_name_t*,		/* src_name */
		    gss_OID*,			/* mech_type */
		    gss_buffer_t,		/* output_token */
		    OM_uint32*,			/* ret_flags */
		    OM_uint32*,			/* time_rec */
		    gss_cred_id_t*		/* delegated_cred_handle */
		    );
    OM_uint32       (*gss_process_context_token)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_ctx_id_t,	/* context_handle */
		    gss_buffer_t	/* token_buffer */
		    );
    OM_uint32       (*gss_delete_sec_context)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_ctx_id_t*,	/* context_handle */
		    gss_buffer_t	/* output_token */
		    );
    OM_uint32       (*gss_context_time)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_ctx_id_t,	/* context_handle */
		    OM_uint32*		/* time_rec */
		    );
    OM_uint32       (*gss_sign)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_ctx_id_t,	/* context_handle */
		    int,		/* qop_req */
		    gss_buffer_t,	/* message_buffer */
		    gss_buffer_t	/* message_token */
		    );
    OM_uint32       (*gss_verify)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_ctx_id_t,	/* context_handle */
		    gss_buffer_t,	/* message_buffer */
		    gss_buffer_t,	/* token_buffer */
		    int*		/* qop_state */
		    );
    OM_uint32       (*gss_seal)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_ctx_id_t,	/* context_handle */
		    int,		/* conf_req_flag */
		    int,		/* qop_req */
		    gss_buffer_t,	/* input_message_buffer */
		    int*,		/* conf_state */
		    gss_buffer_t	/* output_message_buffer */
		    );
    OM_uint32       (*gss_unseal)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_ctx_id_t,	/* context_handle */
		    gss_buffer_t,	/* input_message_buffer */
		    gss_buffer_t,	/* output_message_buffer */
		    int*,		/* conf_state */
		    int*		/* qop_state */
		    );
    OM_uint32       (*gss_display_status)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    OM_uint32,		/* status_value */
		    int,		/* status_type */
		    gss_OID,		/* mech_type */
		    OM_uint32*,		/* message_context */
		    gss_buffer_t	/* status_string */
		    );
    OM_uint32       (*gss_indicate_mechs)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_OID_set*	/* mech_set */
		    );
    OM_uint32       (*gss_compare_name)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_name_t,		/* name1 */
		    gss_name_t,		/* name2 */
		    int*		/* name_equal */
		    );
    OM_uint32       (*gss_display_name)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_name_t,		/* input_name */
		    gss_buffer_t,	/* output_name_buffer */
		    gss_OID*		/* output_name_type */
		    );
    OM_uint32       (*gss_import_name)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_buffer_t,	/* input_name_buffer */
		    gss_OID,		/* input_name_type */
		    gss_name_t*		/* output_name */
		    );
    OM_uint32       (*gss_release_name)
	(
		    void*,		/* context */
		    OM_uint32*,		/* minor_status */
		    gss_name_t*		/* input_name */
		    );
    OM_uint32       (*gss_inquire_cred)
	(
		    void*,			/* context */
		    OM_uint32 *,		/* minor_status */
		    gss_cred_id_t,		/* cred_handle */
		    gss_name_t *,		/* name */
		    OM_uint32 *,		/* lifetime */
		    int *,			/* cred_usage */
		    gss_OID_set *		/* mechanisms */
		    );
    OM_uint32	    (*gss_add_cred)
	(
		    void*,		/* context */
		    OM_uint32 *,	/* minor_status */
		    gss_cred_id_t,	/* input_cred_handle */
		    gss_name_t,		/* desired_name */
		    gss_OID,		/* desired_mech */
		    gss_cred_usage_t,	/* cred_usage */
		    OM_uint32,		/* initiator_time_req */
		    OM_uint32,		/* acceptor_time_req */
		    gss_cred_id_t *,	/* output_cred_handle */
		    gss_OID_set *,	/* actual_mechs */
		    OM_uint32 *,	/* initiator_time_rec */
		    OM_uint32 *		/* acceptor_time_rec */
		    );
    OM_uint32	    (*gss_export_sec_context)
	(
		    void*,		/* context */
		    OM_uint32 *,	/* minor_status */
		    gss_ctx_id_t *,	/* context_handle */
		    gss_buffer_t	/* interprocess_token */
		    );
    OM_uint32	    (*gss_import_sec_context)
	(
		    void *,		/* context */
		    OM_uint32 *,	/* minor_status */
		    gss_buffer_t,	/* interprocess_token */
		    gss_ctx_id_t *	/* context_handle */
		    );
    OM_uint32 	    (*gss_inquire_cred_by_mech)
	(
		    void *,		/* context */
		    OM_uint32 *,	/* minor_status */
		    gss_cred_id_t,	/* cred_handle */
		    gss_OID,		/* mech_type */
		    gss_name_t *,	/* name */
		    OM_uint32 *,	/* initiator_lifetime */
		    OM_uint32 *,	/* acceptor_lifetime */
		    gss_cred_usage_t *	/* cred_usage */
		    );
    OM_uint32	    (*gss_inquire_names_for_mech)
	(
		    void *,		/* context */
		    OM_uint32 *,	/* minor_status */
		    gss_OID,		/* mechanism */
		    gss_OID_set *	/* name_types */
		    );
    OM_uint32	(*gss_inquire_context)
	(
		    void *,		/* context */
		    OM_uint32 *,	/* minor_status */
		    gss_ctx_id_t,	/* context_handle */
		    gss_name_t *,	/* src_name */
		    gss_name_t *,	/* targ_name */
		    OM_uint32 *,	/* lifetime_rec */
		    gss_OID *,		/* mech_type */
		    OM_uint32 *,	/* ctx_flags */
		    int *,           	/* locally_initiated */
		    int *		/* open */
		    );
    OM_uint32	    (*gss_internal_release_oid)
	(
		    void *,		/* context */
		    OM_uint32 *,	/* minor_status */
		    gss_OID *		/* OID */
	 );
    OM_uint32	     (*gss_wrap_size_limit)
	(
		    void *,		/* context */
		    OM_uint32 *,	/* minor_status */
		    gss_ctx_id_t,	/* context_handle */
		    int,		/* conf_req_flag */
		    gss_qop_t,		/* qop_req */
		    OM_uint32,		/* req_output_size */
		    OM_uint32 *		/* max_input_size */
	 );
    int		     (*pname_to_uid)
	(
		    void *,		/* context */
		    char *,		/* pname */
		    gss_OID,		/* name type */
		    gss_OID,		/* mech type */
		    uid_t *		/* uid */
		    );

} *gss_mechanism;

/********************************************************/
/* Internal mechglue routines */

gss_mechanism __gss_get_mechanism (gss_OID);
OM_uint32 __gss_get_mech_type (gss_OID, gss_buffer_t);
OM_uint32 __gss_import_internal_name (OM_uint32 *, gss_OID, gss_union_name_t,
				      gss_name_t *);
OM_uint32 __gss_display_internal_name (OM_uint32 *, gss_OID, gss_name_t,
				       gss_buffer_t, gss_OID *);
OM_uint32 __gss_release_internal_name (OM_uint32 *, gss_OID, gss_name_t *);

OM_uint32 __gss_convert_name_to_union_name
	  (OM_uint32 *,		/* minor_status */
	   gss_mechanism,	/* mech */
	   gss_name_t,		/* internal_name */
	   gss_name_t *		/* external_name */
	   );
gss_cred_id_t __gss_get_mechanism_cred
	  (gss_union_cred_t,	/* union_cred */
	   gss_OID		/* mech_type */
	   );

OM_uint32 generic_gss_release_oid
	   (OM_uint32 *,	/* minor_status */
	    gss_OID *		/* oid */
	   );

OM_uint32 generic_gss_copy_oid
	   (OM_uint32 *,	/* minor_status */
	    gss_OID,		/* oid */
	    gss_OID *		/* new_oid */
	    );

OM_uint32 generic_gss_create_empty_oid_set
	   (OM_uint32 *,	/* minor_status */
	    gss_OID_set *	/* oid_set */
	   );

OM_uint32 generic_gss_add_oid_set_member
	   (OM_uint32 *,	/* minor_status */
	    gss_OID,		/* member_oid */
	    gss_OID_set *	/* oid_set */
	   );

OM_uint32 generic_gss_test_oid_set_member
	   (OM_uint32 *,	/* minor_status */
	    gss_OID,		/* member */
	    gss_OID_set,	/* set */
	    int *		/* present */
	   );

OM_uint32 generic_gss_oid_to_str
 (OM_uint32 *,	/* minor_status */
	    gss_OID,		/* oid */
	    gss_buffer_t	/* oid_str */
	   );

OM_uint32 generic_gss_str_to_oid
	   (OM_uint32 *,	/* minor_status */
	    gss_buffer_t,	/* oid_str */
	    gss_OID *		/* oid */
	   );


gss_OID gss_find_mechanism_from_name_type (gss_OID); /* name_type */

OM_uint32 gss_add_mech_name_type
	   (OM_uint32 *,	/* minor_status */
	    gss_OID,		/* name_type */
	    gss_OID		/* mech */
	       );

#endif /* _GSS_MECHGLUEP_H */

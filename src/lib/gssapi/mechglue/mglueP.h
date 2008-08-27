/* #ident  "@(#)mglueP.h 1.2     96/01/18 SMI" */

/*
 * This header contains the private mechglue definitions.
 *
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _GSS_MECHGLUEP_H
#define _GSS_MECHGLUEP_H

#include "autoconf.h"
#include "mechglue.h"
#include "gssapiP_generic.h"

#define	g_OID_copy(o1, o2)					\
do {								\
	memcpy((o1)->elements, (o2)->elements, (o2)->length);	\
	(o1)->length = (o2)->length;				\
} while (0)

#define	GSS_EMPTY_BUFFER(buf)	((buf) == NULL ||\
	(buf)->value == NULL || (buf)->length == 0)

/*
 * Array of context IDs typed by mechanism OID
 */
typedef struct gss_ctx_id_struct {
	struct gss_ctx_id_struct *loopback;
	gss_OID			mech_type;
	gss_ctx_id_t		internal_ctx_id;
} gss_union_ctx_id_desc, *gss_union_ctx_id_t;

/*
 * Generic GSSAPI names.  A name can either be a generic name, or a
 * mechanism specific name....
 */
typedef struct gss_name_struct {
	struct gss_name_struct *loopback;
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
	OM_uint32		creation_time;
	OM_uint32		time_rec;
	int			cred_usage;
} gss_union_cred_auxinfo;

/*
 * Set of Credentials typed on mechanism OID
 */
typedef struct gss_cred_id_struct {
	struct gss_cred_id_struct *loopback;
	int			count;
	gss_OID			mechs_array;
	gss_cred_id_t		*cred_array;
	gss_union_cred_auxinfo	auxinfo;
} gss_union_cred_desc, *gss_union_cred_t;
 
/*
 * Rudimentary pointer validation macro to check whether the
 * "loopback" field of an opaque struct points back to itself.  This
 * field also catches some programming errors where an opaque pointer
 * is passed to a function expecting the address of the opaque
 * pointer.
 */
#define GSSINT_CHK_LOOP(p) (!((p) != NULL && (p)->loopback == (p)))

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
    OM_uint32	    priority;
    char *	    mechNameStr;
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
	OM_uint32		(*gss_export_name)
	(
		void *,			/* context */
		OM_uint32 *,		/* minor_status */
		const gss_name_t,	/* input_name */
		gss_buffer_t		/* exported_name */
	/* */);
	OM_uint32	(*gss_store_cred)
	(
		void *,			/* context */
		OM_uint32 *,		/* minor_status */
		const gss_cred_id_t,	/* input_cred */
		gss_cred_usage_t,	/* cred_usage */
		const gss_OID,		/* desired_mech */
		OM_uint32,		/* overwrite_cred */
		OM_uint32,		/* default_cred */
		gss_OID_set *,		/* elements_stored */
		gss_cred_usage_t *	/* cred_usage_stored */
	/* */);
} *gss_mechanism;

/*
 * In the user space we use a wrapper structure to encompass the
 * mechanism entry points.  The wrapper contain the mechanism
 * entry points and other data which is only relevant to the gss-api
 * layer.  In the kernel we use only the gss_config strucutre because
 * the kernal does not cantain any of the extra gss-api specific data.
 */
typedef struct gss_mech_config {
	char *kmodName;			/* kernel module name */
	char *uLibName;			/* user library name */
	char *mechNameStr;		/* mechanism string name */
	char *optionStr;		/* optional mech parameters */
	void *dl_handle;		/* RTLD object handle for the mech */
	gss_OID mech_type;		/* mechanism oid */
	gss_mechanism mech;		/* mechanism initialization struct */
	struct gss_mech_config *next;	/* next element in the list */
} *gss_mech_info;

/* Mechanisms defined within our library */

extern gss_mechanism *krb5_gss_get_mech_configs(void);
extern gss_mechanism *spnego_gss_get_mech_configs(void);

/********************************************************/
/* Internal mechglue routines */

int gssint_mechglue_init(void);
void gssint_mechglue_fini(void);

gss_mechanism gssint_get_mechanism (gss_OID);
OM_uint32 gssint_get_mech_type (gss_OID, gss_buffer_t);
char *gssint_get_kmodName(const gss_OID);
char *gssint_get_modOptions(const gss_OID);
OM_uint32 gssint_import_internal_name (OM_uint32 *, gss_OID, gss_union_name_t,
				      gss_name_t *);
OM_uint32 gssint_export_internal_name(OM_uint32 *, const gss_OID,
	const gss_name_t, gss_buffer_t);
OM_uint32 gssint_display_internal_name (OM_uint32 *, gss_OID, gss_name_t,
				       gss_buffer_t, gss_OID *);
OM_uint32 gssint_release_internal_name (OM_uint32 *, gss_OID, gss_name_t *);

OM_uint32 gssint_convert_name_to_union_name
	  (OM_uint32 *,		/* minor_status */
	   gss_mechanism,	/* mech */
	   gss_name_t,		/* internal_name */
	   gss_name_t *		/* external_name */
	   );
gss_cred_id_t gssint_get_mechanism_cred
	  (gss_union_cred_t,	/* union_cred */
	   gss_OID		/* mech_type */
	   );

OM_uint32 gssint_create_copy_buffer(
	const gss_buffer_t,	/* src buffer */
	gss_buffer_t *,		/* destination buffer */
	int			/* NULL terminate buffer ? */
);

OM_uint32 gssint_copy_oid_set(
	OM_uint32 *,			/* minor_status */
	const gss_OID_set_desc * const,	/* oid set */
	gss_OID_set *			/* new oid set */
);

gss_OID gss_find_mechanism_from_name_type (gss_OID); /* name_type */

OM_uint32 gss_add_mech_name_type
	   (OM_uint32 *,	/* minor_status */
	    gss_OID,		/* name_type */
	    gss_OID		/* mech */
	       );

/*
 * Sun extensions to GSS-API v2
 */

OM_uint32
gssint_mech_to_oid(
	const char *mech,		/* mechanism string name */
	gss_OID *oid			/* mechanism oid */
);

const char *
gssint_oid_to_mech(
	const gss_OID oid		/* mechanism oid */
);

OM_uint32
gssint_get_mechanisms(
	char *mechArray[],		/* array to populate with mechs */
	int arrayLen			/* length of passed in array */
);

OM_uint32
gss_store_cred(
	OM_uint32 *,		/* minor_status */
	const gss_cred_id_t,	/* input_cred_handle */
	gss_cred_usage_t,	/* cred_usage */
	const gss_OID,		/* desired_mech */
	OM_uint32,		/* overwrite_cred */
	OM_uint32,		/* default_cred */
	gss_OID_set *,		/* elements_stored */
	gss_cred_usage_t *	/* cred_usage_stored */
);

int
gssint_get_der_length(
	unsigned char **,	/* buf */
	unsigned int,		/* buf_len */
	unsigned int *		/* bytes */
);

unsigned int
gssint_der_length_size(unsigned int /* len */);

int
gssint_put_der_length(
	unsigned int,		/* length */
	unsigned char **,	/* buf */
	unsigned int		/* max_len */
);

/* Use this to map an error code that was returned from a mech
   operation; the mech will be asked to produce the associated error
   messages.

   Remember that if the minor status code cannot be returned to the
   caller (e.g., if it's stuffed in an automatic variable and then
   ignored), then we don't care about producing a mapping.  */
#define map_error(MINORP, MECH) \
    (*(MINORP) = gssint_mecherrmap_map(*(MINORP), &(MECH)->mech_type))
#define map_error_oid(MINORP, MECHOID) \
    (*(MINORP) = gssint_mecherrmap_map(*(MINORP), (MECHOID)))

/* Use this to map an errno value or com_err error code being
   generated within the mechglue code (e.g., by calling generic oid
   ops).  Any errno or com_err values produced by mech operations
   should be processed with map_error.  This means they'll be stored
   separately even if the mech uses com_err, because we can't assume
   that it will use com_err.  */
#define map_errcode(MINORP) \
    (*(MINORP) = gssint_mecherrmap_map_errcode(*(MINORP)))

#endif /* _GSS_MECHGLUEP_H */

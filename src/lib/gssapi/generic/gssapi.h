/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _GSSAPI_H_
#define _GSSAPI_H_

/* for general config: */
#ifndef NO_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>

/*
 * First, define the platform-dependent types.
 */

#ifdef _MSDOS
#define GSS_SIZEOF_INT      2
#define GSS_SIZEOF_SHORT    2
#define GSS_SIZEOF_LONG     4

#ifndef INTERFACE
#define INTERFACE   __far __export __pascal
#define INTERFACE_C __far __export __cdecl
#endif /* INTERFACE */

#ifndef FAR
#define FAR     _far
#endif /* FAR */
#else /* _MSDOS */
/*
 * XXX we need to fix this to be modified by autoconf...
 */
#define GSS_SIZEOF_INT 4
#define GSS_SIZEOF_LONG 4
#define GSS_SIZEOF_SHORT 2
#ifndef FAR
#define FAR
#define INTERFACE
#endif /* FAR */
#endif

#if (GSS_SIZEOF_INT == 4)
typedef unsigned int OM_uint32;
#elif (GSS_SIZEOF_LONG == 4)
typedef unsigned long OM_uint32;
#elif (GSS_SIZEOF_SHORT == 4)
typedef unsigned short OM_uint32;
#endif

typedef void FAR * gss_name_t;
typedef void FAR * gss_cred_id_t;
typedef void FAR * gss_ctx_id_t;

#if !defined(PROTOTYPE)
#if defined(__STDC__) || defined(_WINDOWS)
#define PROTOTYPE(x) x
#else
#define PROTOTYPE(x) ()
#endif
#endif

/*
 * Note that a platform supporting the xom.h X/Open header file
 * may make use of that header for the definitions of OM_uint32
 * and the structure to which gss_OID_desc equates.
 */

typedef struct gss_OID_desc_struct {
      OM_uint32 length;
      void      FAR *elements;
} gss_OID_desc, FAR *gss_OID;

typedef const gss_OID_desc FAR * const const_gss_OID;

typedef struct gss_OID_set_desc_struct  {
      int     count;
      gss_OID elements;
} gss_OID_set_desc, FAR *gss_OID_set;

typedef struct gss_buffer_desc_struct {
      size_t length;
      void FAR *value;
} gss_buffer_desc, FAR *gss_buffer_t;

typedef struct gss_channel_bindings_struct {
      OM_uint32 initiator_addrtype;
      gss_buffer_desc initiator_address;
      OM_uint32 acceptor_addrtype;
      gss_buffer_desc acceptor_address;
      gss_buffer_desc application_data;
} FAR *gss_channel_bindings_t;


/*
 * Six independent flags each of which indicates that a context
 * supports a specific service option.
 */
#define GSS_C_DELEG_FLAG 1
#define GSS_C_MUTUAL_FLAG 2
#define GSS_C_REPLAY_FLAG 4
#define GSS_C_SEQUENCE_FLAG 8
#define GSS_C_CONF_FLAG 16
#define GSS_C_INTEG_FLAG 32


/*
 * Credential usage options
 */
#define GSS_C_BOTH 0
#define GSS_C_INITIATE 1
#define GSS_C_ACCEPT 2

/*
 * Status code types for gss_display_status
 */
#define GSS_C_GSS_CODE 1
#define GSS_C_MECH_CODE 2

/*
 * The constant definitions for channel-bindings address families
 */
#define GSS_C_AF_UNSPEC     0
#define GSS_C_AF_LOCAL      1
#define GSS_C_AF_INET       2
#define GSS_C_AF_IMPLINK    3
#define GSS_C_AF_PUP        4
#define GSS_C_AF_CHAOS      5
#define GSS_C_AF_NS         6
#define GSS_C_AF_NBS        7
#define GSS_C_AF_ECMA       8
#define GSS_C_AF_DATAKIT    9
#define GSS_C_AF_CCITT      10
#define GSS_C_AF_SNA        11
#define GSS_C_AF_DECnet     12
#define GSS_C_AF_DLI        13
#define GSS_C_AF_LAT        14
#define GSS_C_AF_HYLINK     15
#define GSS_C_AF_APPLETALK  16
#define GSS_C_AF_BSC        17
#define GSS_C_AF_DSS        18
#define GSS_C_AF_OSI        19
#define GSS_C_AF_X25        21

#define GSS_C_AF_NULLADDR   255

#define GSS_C_NO_BUFFER ((gss_buffer_t) 0)
#define GSS_C_NULL_OID ((gss_OID) 0)
#define GSS_C_NULL_OID_SET ((gss_OID_set) 0)
#define GSS_C_NO_NAME ((gss_name_t) 0)
#define GSS_C_NO_CONTEXT ((gss_ctx_id_t) 0)
#define GSS_C_NO_CREDENTIAL ((gss_cred_id_t) 0)
#define GSS_C_NO_CHANNEL_BINDINGS ((gss_channel_bindings_t) 0)
#define GSS_C_EMPTY_BUFFER {0, NULL}

/*
 * Define the default Quality of Protection for per-message
 * services.  Note that an implementation that offers multiple
 * levels of QOP may either reserve a value (for example zero,
 * as assumed here) to mean "default protection", or alternatively
 * may simply equate GSS_C_QOP_DEFAULT to a specific explicit QOP
 * value.
 */
#define GSS_C_QOP_DEFAULT 0

/*
 * Expiration time of 2^32-1 seconds means infinite lifetime for a
 * credential or security context
 */
#define GSS_C_INDEFINITE 0xffffffff


/* Major status codes */

#define GSS_S_COMPLETE 0

/*
 * Some "helper" definitions to make the status code macros obvious.
 */
#define GSS_C_CALLING_ERROR_OFFSET 24
#define GSS_C_ROUTINE_ERROR_OFFSET 16
#define GSS_C_SUPPLEMENTARY_OFFSET 0
#define GSS_C_CALLING_ERROR_MASK 0377
#define GSS_C_ROUTINE_ERROR_MASK 0377
#define GSS_C_SUPPLEMENTARY_MASK 0177777

/*
 * The macros that test status codes for error conditions
 */
#define GSS_CALLING_ERROR(x) \
  ((x) & (GSS_C_CALLING_ERROR_MASK << GSS_C_CALLING_ERROR_OFFSET))
#define GSS_ROUTINE_ERROR(x) \
  ((x) & (GSS_C_ROUTINE_ERROR_MASK << GSS_C_ROUTINE_ERROR_OFFSET))
#define GSS_SUPPLEMENTARY_INFO(x) \
  ((x) & (GSS_C_SUPPLEMENTARY_MASK << GSS_C_SUPPLEMENTARY_OFFSET))
#define GSS_ERROR(x) \
  ((GSS_CALLING_ERROR(x) != 0) || (GSS_ROUTINE_ERROR(x) != 0))

/* XXXX these are not part of the GSSAPI C bindings!  (but should be) */

#define GSS_CALLING_ERROR_FIELD(x) \
   (((x) >> GSS_C_CALLING_ERROR_OFFSET) & GSS_C_CALLING_ERROR_MASK)
#define GSS_ROUTINE_ERROR_FIELD(x) \
   (((x) >> GSS_C_ROUTINE_ERROR_OFFSET) & GSS_C_ROUTINE_ERROR_MASK)
#define GSS_SUPPLEMENTARY_INFO_FIELD(x) \
   (((x) >> GSS_C_SUPPLEMENTARY_OFFSET) & GSS_C_SUPPLEMENTARY_MASK)

/*
 * Now the actual status code definitions
 */

/*
 * Calling errors:
 */
#define GSS_S_CALL_INACCESSIBLE_READ \
                             (1 << GSS_C_CALLING_ERROR_OFFSET)
#define GSS_S_CALL_INACCESSIBLE_WRITE \
                             (2 << GSS_C_CALLING_ERROR_OFFSET)
#define GSS_S_CALL_BAD_STRUCTURE \
                             (3 << GSS_C_CALLING_ERROR_OFFSET)

/*
 * Routine errors:
 */
#define GSS_S_BAD_MECH (1 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_NAME (2 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_NAMETYPE (3 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_BINDINGS (4 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_STATUS (5 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_BAD_SIG (6 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_NO_CRED (7 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_NO_CONTEXT (8 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_DEFECTIVE_TOKEN (9 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_DEFECTIVE_CREDENTIAL (10 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_CREDENTIALS_EXPIRED (11 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_CONTEXT_EXPIRED (12 << GSS_C_ROUTINE_ERROR_OFFSET)
#define GSS_S_FAILURE (13 << GSS_C_ROUTINE_ERROR_OFFSET)
/* XXXX This is a necessary evil until the spec is fixed */
#define GSS_S_CRED_UNAVAIL GSS_S_FAILURE

/*
 * Supplementary info bits:
 */
#define GSS_S_CONTINUE_NEEDED (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 0))
#define GSS_S_DUPLICATE_TOKEN (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 1))
#define GSS_S_OLD_TOKEN (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 2))
#define GSS_S_UNSEQ_TOKEN (1 << (GSS_C_SUPPLEMENTARY_OFFSET + 3))


/*
 * Finally, function prototypes for the GSSAPI routines.
 */

OM_uint32 INTERFACE gss_acquire_cred
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_name_t,         /* desired_name */
            OM_uint32,        	/* time_req */
            gss_OID_set,      	/* desired_mechs */
            int,              	/* cred_usage */
            gss_cred_id_t FAR *,/* output_cred_handle */
            gss_OID_set FAR *,  /* actual_mechs */
            OM_uint32 FAR *     /* time_rec */
           ));

OM_uint32 INTERFACE gss_release_cred
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_cred_id_t FAR * /* cred_handle */
           ));

OM_uint32 INTERFACE gss_init_sec_context
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_cred_id_t,    	/* claimant_cred_handle */
            gss_ctx_id_t FAR *, /* context_handle */
            gss_name_t,       	/* target_name */
            const_gss_OID,   	/* mech_type */
            int,              	/* req_flags */
            OM_uint32,        	/* time_req */
            gss_channel_bindings_t,
                              	/* input_chan_bindings */
            gss_buffer_t,     	/* input_token */
            gss_OID FAR *,      /* actual_mech_type */
            gss_buffer_t,     	/* output_token */
            int FAR *,          /* ret_flags */
            OM_uint32 FAR *     /* time_rec */
           ));

OM_uint32 INTERFACE gss_accept_sec_context
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_ctx_id_t FAR *, /* context_handle */
            gss_cred_id_t,    	/* verifier_cred_handle */
            gss_buffer_t,     	/* input_token_buffer */
            gss_channel_bindings_t,
                              	/* input_chan_bindings */
            gss_name_t FAR *,   /* src_name */
            gss_OID FAR *,      /* mech_type */
            gss_buffer_t,     	/* output_token */
            int FAR *,          /* ret_flags */
            OM_uint32 FAR *,    /* time_rec */
            gss_cred_id_t FAR * /* delegated_cred_handle */
           ));

OM_uint32 INTERFACE gss_process_context_token
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_ctx_id_t,     	/* context_handle */
            gss_buffer_t      	/* token_buffer */
           ));

OM_uint32 INTERFACE gss_delete_sec_context
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_ctx_id_t FAR *, /* context_handle */
            gss_buffer_t      	/* output_token */
           ));

OM_uint32 INTERFACE gss_context_time
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_ctx_id_t,     	/* context_handle */
            OM_uint32 FAR *     /* time_rec */
           ));

OM_uint32 INTERFACE gss_sign
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_ctx_id_t,     	/* context_handle */
            int,              	/* qop_req */
            gss_buffer_t,     	/* message_buffer */
            gss_buffer_t      	/* message_token */
           ));

OM_uint32 INTERFACE gss_verify
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_ctx_id_t,     	/* context_handle */
            gss_buffer_t,     	/* message_buffer */
            gss_buffer_t,     	/* token_buffer */
            int FAR *           /* qop_state */
           ));

OM_uint32 INTERFACE gss_seal
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_ctx_id_t,     	/* context_handle */
            int,              	/* conf_req_flag */
            int,              	/* qop_req */
            gss_buffer_t,     	/* input_message_buffer */
            int FAR *,          /* conf_state */
            gss_buffer_t      	/* output_message_buffer */
           ));

OM_uint32 INTERFACE gss_unseal
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_ctx_id_t,     	/* context_handle */
            gss_buffer_t,     	/* input_message_buffer */
            gss_buffer_t,     	/* output_message_buffer */
            int FAR *,          /* conf_state */
            int FAR *           /* qop_state */
           ));

OM_uint32 INTERFACE gss_display_status
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            OM_uint32,        	/* status_value */
            int,              	/* status_type */
            const_gss_OID,    	/* mech_type */
            int FAR *,          /* message_context */
            gss_buffer_t      	/* status_string */
           ));

OM_uint32 INTERFACE gss_indicate_mechs
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_OID_set FAR *   /* mech_set */
           ));

OM_uint32 INTERFACE gss_compare_name
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_name_t,       	/* name1 */
            gss_name_t,       	/* name2 */
            int FAR *           /* name_equal */
           ));

OM_uint32 INTERFACE gss_display_name
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_name_t,      	/* input_name */
            gss_buffer_t,     	/* output_name_buffer */
            gss_OID FAR *       /* output_name_type */
           ));

OM_uint32 INTERFACE gss_import_name
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_buffer_t,     	/* input_name_buffer */
            const_gss_OID,    	/* input_name_type */
            gss_name_t FAR *    /* output_name */
           ));

OM_uint32 INTERFACE gss_release_name
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_name_t FAR *    /* input_name */
           ));

OM_uint32 INTERFACE gss_release_buffer
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_buffer_t      	/* buffer */
           ));

OM_uint32 INTERFACE gss_release_oid_set
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_OID_set FAR *   /* set */
           ));

OM_uint32 INTERFACE gss_inquire_cred
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
            gss_cred_id_t,    	/* cred_handle */
            gss_name_t FAR *,   /* name */
            OM_uint32 FAR *,    /* lifetime */
            int FAR *,          /* cred_usage */
            gss_OID_set FAR *   /* mechanisms */
           ));

OM_uint32 INTERFACE gss_inquire_context
PROTOTYPE( (OM_uint32 FAR *,    /* minor_status */
	    gss_ctx_id_t,     	/* context_handle */
	    gss_name_t FAR *,   /* initiator_name */
	    gss_name_t FAR *,   /* acceptor_name */
	    OM_uint32 FAR *,    /* lifetime_rec */
	    gss_OID FAR *,      /* mech_type */
	    int FAR *,          /* ret_flags */
	    int FAR *           /* locally_initiated */
	   ));

OM_uint32 INTERFACE gss_export_sec_context
PROTOTYPE( (OM_uint32 FAR *,	/* minor_status */
	    gss_ctx_id_t FAR *,	/* context_handle */
	    gss_buffer_t	/* interprocess_token */
	    ));

OM_uint32 INTERFACE gss_import_sec_context
PROTOTYPE( (OM_uint32 FAR *,	/* minor_status */
	    gss_buffer_t,	/* interprocess_token */
	    gss_ctx_id_t FAR *	/* context_handle */
	    ));
#endif /* _GSSAPI_H_ */

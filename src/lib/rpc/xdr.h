/* @(#)xdr.h	2.2 88/07/29 4.0 RPCSRC */
/*
 * Sun RPC is a product of Sun Microsystems, Inc. and is provided for
 * unrestricted use provided that this legend is included on all tape
 * media and as a part of the software program in whole or part.  Users
 * may copy or modify Sun RPC without charge, but are not authorized
 * to license or distribute it to anyone else except as part of a product or
 * program developed by the user.
 * 
 * SUN RPC IS PROVIDED AS IS WITH NO WARRANTIES OF ANY KIND INCLUDING THE
 * WARRANTIES OF DESIGN, MERCHANTIBILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE, OR ARISING FROM A COURSE OF DEALING, USAGE OR TRADE PRACTICE.
 * 
 * Sun RPC is provided with no support and without any obligation on the
 * part of Sun Microsystems, Inc. to assist in its use, correction,
 * modification or enhancement.
 * 
 * SUN MICROSYSTEMS, INC. SHALL HAVE NO LIABILITY WITH RESPECT TO THE
 * INFRINGEMENT OF COPYRIGHTS, TRADE SECRETS OR ANY PATENTS BY SUN RPC
 * OR ANY PART THEREOF.
 * 
 * In no event will Sun Microsystems, Inc. be liable for any lost revenue
 * or profits or other special, indirect and consequential damages, even if
 * Sun has been advised of the possibility of such damages.
 * 
 * Sun Microsystems, Inc.
 * 2550 Garcia Avenue
 * Mountain View, California  94043
 */
/*      @(#)xdr.h 1.19 87/04/22 SMI      */

/*
 * xdr.h, External Data Representation Serialization Routines.
 *
 * Copyright (C) 1984, Sun Microsystems, Inc.
 */

#ifndef __XDR_HEADER__
#define __XDR_HEADER__

/* We need FILE.  */
#include <stdio.h>

/*
 * XDR provides a conventional way for converting between C data
 * types and an external bit-string representation.  Library supplied
 * routines provide for the conversion on built-in C data types.  These
 * routines and utility routines defined here are used to help implement
 * a type encode/decode routine for each user-defined type.
 *
 * Each data type provides a single procedure which takes two arguments:
 *
 *	bool_t
 *	xdrproc(xdrs, argresp)
 *		XDR *xdrs;
 *		<type> *argresp;
 *
 * xdrs is an instance of a XDR handle, to which or from which the data
 * type is to be converted.  argresp is a pointer to the structure to be
 * converted.  The XDR handle contains an operation field which indicates
 * which of the operations (ENCODE, DECODE * or FREE) is to be performed.
 *
 * XDR_DECODE may allocate space if the pointer argresp is null.  This
 * data can be freed with the XDR_FREE operation.
 *
 * We write only one procedure per data type to make it easy
 * to keep the encode and decode procedures for a data type consistent.
 * In many cases the same code performs all operations on a user defined type,
 * because all the hard work is done in the component type routines.
 * decode as a series of calls on the nested data types.
 */

/*
 * Xdr operations.  XDR_ENCODE causes the type to be encoded into the
 * stream.  XDR_DECODE causes the type to be extracted from the stream.
 * XDR_FREE can be used to release the space allocated by an XDR_DECODE
 * request.
 */
enum xdr_op {
	XDR_ENCODE=0,
	XDR_DECODE=1,
	XDR_FREE=2
};

/*
 * This is the number of bytes per unit of external data.
 */
#define BYTES_PER_XDR_UNIT	(4)
#define RNDUP(x)  ((((x) + BYTES_PER_XDR_UNIT - 1) / BYTES_PER_XDR_UNIT) \
		    * BYTES_PER_XDR_UNIT)

/*
 * A xdrproc_t exists for each data type which is to be encoded or decoded.
 *
 * The second argument to the xdrproc_t is a pointer to an opaque pointer.
 * The opaque pointer generally points to a structure of the data type
 * to be decoded.  If this pointer is 0, then the type routines should
 * allocate dynamic storage of the appropriate size and return it.
 * bool_t	(*xdrproc_t)(XDR *, caddr_t *);
 *
 * XXX can't actually prototype it, because some take three args!!!
 */
typedef	bool_t (*xdrproc_t)();

/*
 * The XDR handle.
 * Contains operation which is being applied to the stream,
 * an operations vector for the paticular implementation (e.g. see xdr_mem.c),
 * and two private fields for the use of the particular impelementation.
 */
typedef struct __xdr_s {
	enum xdr_op	x_op;		/* operation; fast additional param */
	struct xdr_ops {
	    /* get a long from underlying stream */
	    bool_t	(*x_getlong)(struct __xdr_s *, long *);

            /* put a long to underlying stream */
	    bool_t	(*x_putlong)(struct __xdr_s *, long *);	

            /* get some bytes from underlying stream */
	    bool_t	(*x_getbytes)(struct __xdr_s *, caddr_t, unsigned int);

            /* put some bytes to underlying stream */
	    bool_t	(*x_putbytes)(struct __xdr_s *, caddr_t, unsigned int);

            /* returns bytes off from beginning */
	    unsigned int	(*x_getpostn)(struct __xdr_s *);

            /* lets you reposition the stream */
	    bool_t  (*x_setpostn)(struct __xdr_s *, unsigned int);

	    /* buf quick ptr to buffered data */
	    rpc_int32 *	(*x_inline)(struct __xdr_s *, int);	

            /* free privates of this xdr_stream */
	    void	(*x_destroy)(struct __xdr_s *);	
	} *x_ops;
	caddr_t 	x_public;	/* users' data */
	void *		x_private;	/* pointer to private data */
	caddr_t 	x_base;		/* private used for position info */
	int		x_handy;	/* extra private word */
} XDR;

/*
 * Operations defined on a XDR handle
 *
 * XDR		*xdrs;
 * rpc_int32		*longp;
 * caddr_t	 addr;
 * unsigned int	 len;
 * unsigned int	 pos;
 */
#define XDR_GETLONG(xdrs, longp)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, longp)
#define xdr_getlong(xdrs, longp)			\
	(*(xdrs)->x_ops->x_getlong)(xdrs, longp)

#define XDR_PUTLONG(xdrs, longp)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, longp)
#define xdr_putlong(xdrs, longp)			\
	(*(xdrs)->x_ops->x_putlong)(xdrs, longp)

#define XDR_GETBYTES(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)
#define xdr_getbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)

#define XDR_PUTBYTES(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)
#define xdr_putbytes(xdrs, addr, len)			\
	(*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)

#define XDR_GETPOS(xdrs)				\
	(*(xdrs)->x_ops->x_getpostn)(xdrs)
#define xdr_getpos(xdrs)				\
	(*(xdrs)->x_ops->x_getpostn)(xdrs)

#define XDR_SETPOS(xdrs, pos)				\
	(*(xdrs)->x_ops->x_setpostn)(xdrs, pos)
#define xdr_setpos(xdrs, pos)				\
	(*(xdrs)->x_ops->x_setpostn)(xdrs, pos)

#define	XDR_INLINE(xdrs, len)				\
	(*(xdrs)->x_ops->x_inline)(xdrs, len)
#define	xdr_inline(xdrs, len)				\
	(*(xdrs)->x_ops->x_inline)(xdrs, len)

#define	XDR_DESTROY(xdrs)				\
	if ((xdrs)->x_ops->x_destroy) 			\
		(*(xdrs)->x_ops->x_destroy)(xdrs)
#define	xdr_destroy(xdrs)				\
	if ((xdrs)->x_ops->x_destroy) 			\
		(*(xdrs)->x_ops->x_destroy)(xdrs)

/*
 * Support struct for discriminated unions.
 * You create an array of xdrdiscrim structures, terminated with
 * a entry with a null procedure pointer.  The xdr_union routine gets
 * the discriminant value and then searches the array of structures
 * for a matching value.  If a match is found the associated xdr routine
 * is called to handle that part of the union.  If there is
 * no match, then a default routine may be called.
 * If there is no match and no default routine it is an error.
 */
#define NULL_xdrproc_t ((xdrproc_t)0)
struct xdr_discrim {
	int	value;
	xdrproc_t proc;
};

/*
 * In-line routines for fast encode/decode of primitve data types.
 * Caveat emptor: these use single memory cycles to get the
 * data from the underlying buffer, and will fail to operate
 * properly if the data is not aligned.  The standard way to use these
 * is to say:
 *	if ((buf = XDR_INLINE(xdrs, count)) == NULL)
 *		return (FALSE);
 *	<<< macro calls >>>
 * where ``count'' is the number of bytes of data occupied
 * by the primitive data types.
 *
 * N.B. and frozen for all time: each data type here uses 4 bytes
 * of external representation.
 */
#define IXDR_GET_LONG(buf)		((long)ntohl((rpc_u_int32)*(buf)++))
#define IXDR_PUT_LONG(buf, v)		(*(buf)++ = (rpc_int32)htonl((rpc_u_int32)v))

#define IXDR_GET_BOOL(buf)		((bool_t)IXDR_GET_LONG(buf))
#define IXDR_GET_ENUM(buf, t)		((t)IXDR_GET_LONG(buf))
#define IXDR_GET_U_LONG(buf)		((rpc_u_int32)IXDR_GET_LONG(buf))
#define IXDR_GET_SHORT(buf)		((short)IXDR_GET_LONG(buf))
#define IXDR_GET_U_SHORT(buf)		((unsigned short)IXDR_GET_LONG(buf))

#define IXDR_PUT_BOOL(buf, v)		IXDR_PUT_LONG((buf), ((rpc_int32)(v)))
#define IXDR_PUT_ENUM(buf, v)		IXDR_PUT_LONG((buf), ((rpc_int32)(v)))
#define IXDR_PUT_U_LONG(buf, v)		IXDR_PUT_LONG((buf), ((rpc_int32)(v)))
#define IXDR_PUT_SHORT(buf, v)		IXDR_PUT_LONG((buf), ((rpc_int32)(v)))
#define IXDR_PUT_U_SHORT(buf, v)	IXDR_PUT_LONG((buf), ((rpc_int32)(v)))

/*
 * These are the "generic" xdr routines.
 */
#define xdr_void	gssrpc_xdr_void
#define xdr_int		gssrpc_xdr_int
#define xdr_u_int	gssrpc_xdr_u_int
#define xdr_long	gssrpc_xdr_long
#define xdr_u_long	gssrpc_xdr_u_long
#define xdr_short	gssrpc_xdr_short
#define xdr_u_short	gssrpc_xdr_u_short
#define xdr_bool	gssrpc_xdr_bool
#define xdr_enum	gssrpc_xdr_enum
#define xdr_array	gssrpc_xdr_array
#define xdr_bytes	gssrpc_xdr_bytes
#define xdr_opaque	gssrpc_xdr_opaque
#define xdr_string	gssrpc_xdr_string
#define xdr_union	gssrpc_xdr_union
#define xdr_char	gssrpc_xdr_char
#define xdr_u_char	gssrpc_xdr_u_char
#define xdr_vector	gssrpc_xdr_vector
#define xdr_float	gssrpc_xdr_float
#define xdr_double	gssrpc_xdr_double
#define xdr_reference	gssrpc_xdr_reference
#define xdr_pointer	gssrpc_xdr_pointer
#define xdr_wrapstring	gssrpc_xdr_wrapstring

extern bool_t	xdr_void(XDR *, void *);
extern bool_t	xdr_int
(XDR *, int *);
extern bool_t	xdr_u_int
(XDR *, unsigned int *);
extern bool_t	xdr_long
(XDR *, long *);
extern bool_t	xdr_u_long
(XDR *, unsigned long *);
extern bool_t	xdr_short
(XDR *, short *);
extern bool_t	xdr_u_short
(XDR *, unsigned short *);
extern bool_t	xdr_bool
(XDR *, bool_t *);
extern bool_t	xdr_enum
(XDR *, enum_t *);
extern bool_t	xdr_array
(XDR *, caddr_t *, unsigned int*, unsigned int, unsigned int, xdrproc_t);
extern bool_t	xdr_bytes
(XDR *, char **, unsigned int *, unsigned int);
extern bool_t	xdr_opaque
(XDR *, caddr_t, unsigned int);
extern bool_t	xdr_string
(XDR *, char **, unsigned int);
extern bool_t	xdr_union
(XDR *, enum_t *, char *, struct xdr_discrim *, xdrproc_t);
extern bool_t	xdr_char
(XDR *, char *);
extern bool_t	xdr_u_char
(XDR *, unsigned char *);
extern bool_t	xdr_vector
(XDR *, char *, unsigned int, unsigned int, xdrproc_t);
extern bool_t	xdr_float
(XDR *, float *);
extern bool_t	xdr_double
(XDR *, double *);
extern bool_t	xdr_reference
(XDR *, caddr_t *, unsigned int, xdrproc_t);
extern bool_t	xdr_pointer
(XDR *, char **, unsigned int, xdrproc_t);
extern bool_t	xdr_wrapstring
(XDR *, char **);

/*
 * Common opaque bytes objects used by many rpc protocols;
 * declared here due to commonality.
 */
#define xdr_netobj	gssrpc_xdr_netobj
#define xdr_int32	gssrpc_xdr_int32
#define xdr_u_int32	gssrpc_xdr_u_int32

#define MAX_NETOBJ_SZ 1024 
struct netobj {
	unsigned int	n_len;
	char	*n_bytes;
};
typedef struct netobj netobj;
extern bool_t   xdr_netobj
(XDR *, struct netobj *);

extern bool_t	xdr_int32
(XDR *, rpc_int32 *);
extern bool_t	xdr_u_int32
(XDR *, rpc_u_int32 *);

/*
 * These are the public routines for the various implementations of
 * xdr streams.
 */
#define xdrmem_create		gssrpc_xdrmem_create
#define xdrstdio_create		gssrpc_xdrstdio_create
#define xdrrec_create		gssrpc_xdrrec_create
#define xdralloc_create		gssrpc_xdralloc_create
#define xdralloc_release	gssrpc_xdralloc_release
#define xdrrec_endofrecord	gssrpc_xdrrec_endofrecord
#define xdrrec_skiprecord	gssrpc_xdrrec_skiprecord
#define xdrrec_eof		gssrpc_xdrrec_eof
#define xdralloc_getdata	gssrpc_xdralloc_getdata

/* XDR allocating memory buffer */
extern void   xdralloc_create (XDR *xdrs, enum xdr_op op);	

/* destroy xdralloc, save buf */
extern void   xdralloc_release (XDR *xdrs);	

/* get buffer from xdralloc */
extern caddr_t xdralloc_getdata (XDR *xdrs);	

/* XDR using memory buffers */
extern void xdrmem_create (XDR *xdrs, caddr_t addr,
				     unsigned int size, enum xdr_op xop);

/* XDR using stdio library */
extern void xdrstdio_create (XDR *xdrs, FILE *file,
					enum xdr_op op);

/* XDR pseudo records for tcp */
extern void xdrrec_create (XDR *xdrs, unsigned int sendsize,
				     unsigned int recvsize, caddr_t tcp_handle,
				     int (*readit) (caddr_t, caddr_t, int),
				     int (*writeit) (caddr_t, caddr_t, int));

/* make end of xdr record */
extern bool_t xdrrec_endofrecord (XDR *xdrs, bool_t sendnow);

/* move to beginning of next record */
extern bool_t xdrrec_skiprecord (XDR *xdrs);

/* true if no more input */
extern bool_t xdrrec_eof (XDR *xdrs);

/* free memory buffers for xdr */
extern void gssrpc_xdr_free (xdrproc_t proc, void *__objp);
#endif /* !__XDR_HEADER__ */

/* ronote.h - Additions to properly support ABSTRACT-BIND */

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.2  1994/06/15 23:16:26  eichin
 * step 3: bcopy->memcpy or memmove (chose by hand), twiddle args
 *
 * Revision 1.1  1994/06/10 03:29:40  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:18:06  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:38:20  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:33:52  isode
 * Release 7.0
 * 
 * 
 */

/*
 *				  NOTICE
 *
 *    Acquisition, use, and distribution of this module and related
 *    materials are subject to the restrictions of a license agreement.
 *    Consult the Preface in the User's Manual for the full terms of
 *    this agreement.
 *
 */

#ifndef	_RoNot_
#define	_RoNot_

#ifndef	_MANIFEST_
#include "manifest.h"
#endif
#ifndef	_GENERAL_
#include "general.h"
#endif

#ifndef	_AcSAP_
#include "acsap.h"		/* definitions for AcS-USERs */
#endif

#ifndef	_RoSAP_
#include "rosap.h"		/* definitions for RoS-USERs */
#endif

#define BIND_RESULT	1	/* indicates a bind result occured */
#define BIND_ERROR	2	/* indicates a bind error occured */

struct RoNOTindication {
    int	    rni_reason;		/* reason for failure */
#define RBI_ACSE		1	/* ACSE provider failed */
#define RBI_SET_ROSE_PRES	2	/* Failed to set ROS-USER */
#define RBI_ENC_BIND_ARG	3	/* Failed encoding bind argument */
#define RBI_ENC_BIND_RES	4	/* Failed encoding bind result */
#define RBI_ENC_BIND_ERR	5	/* Failed encoding bind error */
#define RBI_ENC_UNBIND_ARG	6	/* Failed encoding unbind argument */
#define RBI_ENC_UNBIND_RES	7	/* Failed encoding unbind result */
#define RBI_ENC_UNBIND_ERR	8	/* Failed encoding unbind error */
#define RBI_DEC_BIND_ARG	9	/* Failed decoding bind argument */
#define RBI_DEC_BIND_RES	10	/* Failed decoding bind result */
#define RBI_DEC_BIND_ERR	11	/* Failed decoding bind error */
#define RBI_DEC_UNBIND_ARG	12	/* Failed decoding unbind argument */
#define RBI_DEC_UNBIND_RES	13	/* Failed decoding unbind result */
#define RBI_DEC_UNBIND_ERR	14	/* Failed decoding unbind error */
#define RBI_DEC_NINFO		15	/* Erroneous number of user infos */

				/* diagnostics from provider */
#define	RB_SIZE	512
    int	    rni_cc;		/*   length */
    char    rni_data[RB_SIZE];	/*   data */
};

#ifndef	lint
#ifndef	__STDC__
#define	copyRoNOTdata(base,len,d) \
{ \
    register int i = len; \
    if ((d -> d/* */_cc = min (i, sizeof d -> d/* */_data)) > 0) \
	memcpy (d -> d/* */_data, base, d -> d/* */_cc); \
}
#else
#define	copyRoNOTdata(base,len,d) \
{ \
    register int i = len; \
    if ((d -> d##_cc = min (i, sizeof d -> d##_data)) > 0) \
	memcpy (d -> d##_data, base, d -> d##_cc); \
}
#endif
#else
#define	copyRoNOTdata(base,len,d)	memcpy ((char *) d, base, len)
#endif

#endif

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:30:44  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  94/06/10  03:19:10  eichin
 * autoconfed isode for kerberos work
 * 
 * Revision 1.1  1994/05/31 20:39:31  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:42:59  isode
 * Release 7.0
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

/*
 * common encoding macro definitions
 */

#define DO_OFFSET(parm, p)	((parm) + (p)->pe_ucode)
#define NO_OFFSET(parm, p)	(parm)

/* various things From Pointer And Offset- *_FPAO */

#define INT_FPAO(parm, p)	(*(integer *)DO_OFFSET(parm, p))

#define REAL_FPAO(parm, p)	(*(double *)DO_OFFSET(parm, p))

#define CHAR_FPAO(parm, p)	(*(char *)DO_OFFSET(parm, p))

#define OID_FPAO(parm, p)	(*(OID *)DO_OFFSET(parm, p))
#define SOID_FPAO(parm, p)	((OID)NO_OFFSET(parm, p))

#define PTR_FPAO(parm, p)	(*(char **)DO_OFFSET(parm, p))
#define SPTR_FPAO(parm, p)	((char *)NO_OFFSET(parm, p))

#define QB_FPAO(parm, p)	(*(struct qbuf **)DO_OFFSET(parm, p))
#define SQB_FPAO(parm, p)	((struct qbuf *)NO_OFFSET(parm, p))

#define PE_FPAO(parm, p)	(*(PE *)DO_OFFSET(parm, p))
#define SPE_FPAO(parm, p)	((PE)NO_OFFSET(parm, p)

#define TYPE2MOD(mod, p)	((mod)->md_etab[p->pe_tag])

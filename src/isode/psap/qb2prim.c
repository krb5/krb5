/* qb2prim.c - octet string to primitive */

/* 
 * isode/psap/qb2prim.c
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


/* LINTLIBRARY */

#include <stdio.h>
#include "psap.h"

/* form: PRIMitive or CONStructor --

	qb2prim  -	octet string (via qbufs) to presentation element

 */

/*  */

PE	qb2prim_aux (qb, class, id, in_line)
register struct qbuf *qb;
PElementClass	class;
PElementID	id;
int	in_line;
{
    register PE	    pe,
		    p;
    register struct qbuf *qp;

    if (qb == NULL)
	return NULLPE;
    
    if ((qp = qb -> qb_forw) == qb || qp -> qb_forw == qb) {
	if ((pe = pe_alloc (class, PE_FORM_PRIM, id)) == NULLPE)
	    return NULLPE;

	if (in_line) {
	    if (pe -> pe_len = qp -> qb_len)
		pe -> pe_prim = (PElementData) qp -> qb_data;
	    pe -> pe_inline = 1;
	}
	else
	    if (pe -> pe_len = qp -> qb_len) {
		if ((pe -> pe_prim = PEDalloc (pe -> pe_len)) == NULLPED)
		    goto no_mem;
		PEDcpy (qp -> qb_data, pe -> pe_prim, pe -> pe_len);
	    }
    }
    else {
	if ((pe = pe_alloc (class, PE_FORM_CONS, id)) == NULLPE)
	    return NULLPE;

	do {
	    if (seq_add (pe, p = pe_alloc (PE_CLASS_UNIV, PE_FORM_PRIM,
					   PE_PRIM_OCTS), -1) == NOTOK) {
no_mem: ;
		pe_free (pe);
		return NULLPE;
	    }

	    p -> pe_len = qp -> qb_len;
	    if (in_line) {
		p -> pe_prim = (PElementData) qp -> qb_data;
		p -> pe_inline = 1;
	    }
	    else {
		if ((p -> pe_prim = PEDalloc (p -> pe_len)) == NULLPED)
		    goto no_mem;
		PEDcpy (qp -> qb_data, p -> pe_prim, p -> pe_len);
	    }

	    qp = qp -> qb_forw;
	}
	while (qp != qb);
    }

    return pe;
}

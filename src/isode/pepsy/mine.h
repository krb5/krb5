/* mine.h */

/* 
 * $Header$
 *
 *
 * $Log$
 * Revision 1.1  1994/06/10 03:30:50  eichin
 * autoconfed isode for kerberos work
 *
 * Revision 1.1  1994/05/31 20:39:42  eichin
 * reduced-isode release from /mit/isode/isode-subset/src
 *
 * Revision 8.0  91/07/17  12:43:02  isode
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


#define TABLESIZE 29

typedef struct ID_TABLE {
	char	*h_value;
	char	*r_value;
	int	def_bit;
	int	def_value;
	int	count;
	struct ID_TABLE	*next;
	} id_entry;

typedef struct S_TABLE {
	char	*name;
	char	*type;
	struct S_TABLE	*parent;
	char	*field;
	int	defined;
	struct S_TABLE *next;
	} s_table;

extern	id_entry	*id_table[];

extern char *c_flags();

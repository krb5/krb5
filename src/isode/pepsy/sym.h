/* sym.h */

/* 
 * isode/pepsy/sym.h
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


typedef struct symlist {
    char   *sy_encpref;
    char   *sy_decpref;
    char   *sy_prfpref;
    char   *sy_module;
    char   *sy_name;

    YP	    sy_type;

    struct symlist *sy_next;
}		symlist, *SY;
#define	NULLSY	((SY) 0)


/*
 * This file is part of libdyn.a, the C Dynamic Object library.  It
 * contains the public header file.
 *
 * There are no restrictions on this code; however, if you make any
 * changes, I request that you document them so that I do not get
 * credit or blame for your modifications.
 *
 * Written by Barr3y Jaspan, Student Information Processing Board (SIPB)
 * and MIT-Project Athena, 1989.
 */


/*
 * dyn.h -- header file to be included by programs linking against
 * libdyn.a.
 */

#ifndef _Dyn_h
#define _Dyn_h

typedef char *DynPtr;
typedef struct _DynObject {
     DynPtr	array;
     int	el_size, num_el, size, inc;
     int	debug, paranoid, initzero;
} DynObjectRec, *DynObject;

/* Function macros */
#define DynHigh(obj)	(DynSize(obj) - 1)
#define DynLow(obj)	(0)

/* Return status codes */
#define DYN_OK		-1000
#define DYN_NOMEM	-1001
#define DYN_BADINDEX	-1002
#define DYN_BADVALUE	-1003
     
/* Function declarations */
#ifdef __STDC__
#define P(args) args
#else
#define P(args) ()
#endif /* __STDC__ */

DynObject DynCreate P((int el_size, int inc)), DynCopy P((DynObject obj));
int DynDestroy P((DynObject obj)), DynRelease P((DynObject obj));
int DynAdd P((DynObject obj, void *el));
int DynPut P((DynObject obj, void *el, int idx));
int DynInsert P((DynObject obj, int idx, void *els, int num));
int DynDelete P((DynObject obj, int idx));
DynPtr DynGet P((DynObject obj, int num));
DynPtr DynArray P((DynObject obj));
int DynDebug P((DynObject obj, int state));
int DynParanoid P((DynObject obj, int state));
int DynInitzero P((DynObject obj, int state));
int DynSize P((DynObject obj));
int DynCapacity P((DynObject obj));

#undef P

#endif /* _Dyn_h */
/* DO NOT ADD ANYTHING AFTER THIS #endif */

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
     
/*@null@*//*@only@*/ DynObject DynCreate (int el_size, int inc);
/*@null@*//*@only@*/ DynObject DynCopy (DynObject obj);
int DynDestroy (/*@only@*/DynObject obj), DynRelease (DynObject obj);
int DynAdd (DynObject obj, void *el);
int DynPut (DynObject obj, void *el, int idx);
int DynInsert (DynObject obj, int idx, /*@observer@*/void *els, int num);
int DynDelete (DynObject obj, int idx);
/*@dependent@*//*@null@*/ DynPtr DynGet (DynObject obj, int num);
/*@observer@*/ DynPtr DynArray (DynObject obj);
int DynDebug (DynObject obj, int state);
int DynParanoid (DynObject obj, int state);
int DynInitzero (DynObject obj, int state);
int DynSize (DynObject obj);
int DynCapacity (DynObject obj);
int DynAppend (DynObject obj, DynPtr els, int num);

#undef P

#endif /* _Dyn_h */
/* DO NOT ADD ANYTHING AFTER THIS #endif */

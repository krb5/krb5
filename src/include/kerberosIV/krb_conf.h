/*
 *	$Source$
 *	$Header$
 *
 *	This file contains configuration information for the DES 
 *	library which is machine specific; currently, this file contains
 *	configuration information for the vax, the "ibm032" (RT),
 *      and the "PC8086" (IBM PC).
 *
 *      Note:  cross-compiled targets must appear BEFORE their
 *      corresponding cross-compiler host.  Otherwise, both will
 *      be defined when running the native compiler on the programs that
 *      construct cross-compiled sources.
 */

#ifdef PC8086
#define IBMPC
#define BITS16
/*#define BIG*/
#define CROSSMSDOS
#define LSBFIRST

#else

#ifdef vax
#define VAX
#define VAXASM
#define BITS32
#define BIG
#define BSDUNIX
#define LSBFIRST

#else

#ifdef ibm032
#define IBMWS
#define IBMWSASM
#define BITS32
#define BIG
#define BSDUNIX
#define MSBFIRST
#define MUSTALIGN

#else

Sorry, you lose.  Figure out what the machine looks like and fix this file to 
include it.

#endif ibm032
#endif vax
#endif pc8086


